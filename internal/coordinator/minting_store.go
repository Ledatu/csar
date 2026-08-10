package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ledatu/csar-core/tokenmint"
)

// ErrDescriptorScopeViolation is returned when a mint descriptor references
// credentials outside its own namespace. It is never expected in normal
// operation: it means either a bug in whatever wrote the descriptor, or an
// attempt to read another tenant's secret. Alert on it.
var ErrDescriptorScopeViolation = errors.New("descriptor references credentials outside its own namespace")

// ErrNestedDescriptor is returned when a descriptor's credential ref resolves
// to another descriptor.
var ErrNestedDescriptor = errors.New("descriptor credential ref resolves to another descriptor")

// MintingTokenStore resolves mint descriptors into live bearer tokens.
//
// It wraps a raw TokenStore: refs holding ordinary stored tokens pass straight
// through untouched, and only descriptors trigger a grant. That is what lets
// the entire feature ship without the router, the x-csar-security schema, or
// any route YAML changing — a minted ref looks exactly like a static one from
// the outside.
//
// It deliberately does NOT implement MutableTokenStore. The admin server's
// copy endpoint fetches a source ref and writes the result to a destination
// ref; if it were handed this decorator, copying a descriptor would silently
// materialize a live bearer token as a permanent stored secret. Keeping the
// write path on the raw store makes that mistake impossible to make.
type MintingTokenStore struct {
	inner  TokenStore
	minter *tokenmint.Minter
	cfg    *tokenmint.Config
	logger *slog.Logger
}

// NewMintingTokenStore wraps inner with descriptor resolution.
func NewMintingTokenStore(inner TokenStore, minter *tokenmint.Minter, cfg *tokenmint.Config, logger *slog.Logger) *MintingTokenStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &MintingTokenStore{inner: inner, minter: minter, cfg: cfg, logger: logger}
}

// LoadAll delegates to the inner store, dropping descriptor entries: a bulk
// load must not fan out into a grant per descriptor.
func (m *MintingTokenStore) LoadAll(ctx context.Context) (map[string]TokenEntry, error) {
	all, err := m.inner.LoadAll(ctx)
	if err != nil {
		return nil, err
	}
	for ref := range all {
		if all[ref].Descriptor != nil {
			delete(all, ref)
		}
	}
	return all, nil
}

// FetchOne resolves a ref, minting a token when the stored object is a
// descriptor.
func (m *MintingTokenStore) FetchOne(ctx context.Context, tokenRef string) (TokenEntry, error) {
	raw, err := m.inner.FetchOne(ctx, tokenRef)
	if err != nil {
		return TokenEntry{}, err
	}
	if raw.Descriptor == nil {
		return raw, nil
	}
	return m.mint(ctx, tokenRef, raw)
}

func (m *MintingTokenStore) mint(ctx context.Context, tokenRef string, raw TokenEntry) (TokenEntry, error) {
	desc := raw.Descriptor

	if err := desc.Validate(); err != nil {
		return TokenEntry{}, fmt.Errorf("token ref %q: %w", tokenRef, err)
	}

	profile, ok := m.cfg.Profile(desc.GrantProfile)
	if !ok {
		// Never fall back to a default profile: that would send a credential
		// to an endpoint nobody chose for it.
		return TokenEntry{}, fmt.Errorf("token ref %q: %w: %q", tokenRef, tokenmint.ErrUnknownProfile, desc.GrantProfile)
	}

	if err := m.checkScope(tokenRef, desc, profile.SecretRefScopeSegments); err != nil {
		return TokenEntry{}, err
	}

	clientID, err := m.fetchSecret(ctx, desc.ClientIDRef)
	if err != nil {
		return TokenEntry{}, fmt.Errorf("token ref %q: client_id_ref %q: %w", tokenRef, desc.ClientIDRef, err)
	}
	clientSecret, err := m.fetchSecret(ctx, desc.ClientSecretRef)
	if err != nil {
		return TokenEntry{}, fmt.Errorf("token ref %q: client_secret_ref %q: %w", tokenRef, desc.ClientSecretRef, err)
	}

	res, err := m.minter.Mint(ctx, desc.GrantProfile, clientID, clientSecret)
	if err != nil {
		return TokenEntry{}, fmt.Errorf("token ref %q: %w", tokenRef, err)
	}

	return TokenEntry{
		EncryptedToken: []byte(res.AccessToken),
		// Minted tokens are plaintext at this boundary by construction: there
		// is no ciphertext to hand a router, so KMS decryption must be skipped.
		Passthrough: true,
		KMSKeyID:    "",
		Version:     raw.Version,
		Mint: &MintInfo{
			RefreshAfter: res.RefreshAfter,
			HardExpiry:   res.HardExpiry,
		},
	}, nil
}

// checkScope confines a descriptor to its own namespace.
//
// This is the single most important control in the minting path. Any service
// with write access to a token prefix can author a descriptor, and a
// descriptor names the refs whose contents get sent to a token endpoint and
// come back as an injectable Bearer header. Without this check a descriptor
// would be an arbitrary read primitive over the whole token store: point one
// at another tenant's secret, or at a shared platform credential, and read it
// straight back out through a route you control.
//
// Requiring the credential refs to share the descriptor's own leading path
// segments — accounts/{marketplace}/{external_id}/ for the standard three —
// means a descriptor can only ever reach credentials that already belong to
// the account it serves.
func (m *MintingTokenStore) checkScope(tokenRef string, desc *tokenmint.Descriptor, segments int) error {
	scope, err := refScope(tokenRef, segments)
	if err != nil {
		return fmt.Errorf("token ref %q: %w", tokenRef, err)
	}

	for _, ref := range []string{desc.ClientIDRef, desc.ClientSecretRef} {
		if err := ValidateTokenRef(ref); err != nil {
			return fmt.Errorf("token ref %q: credential ref %q is malformed: %w", tokenRef, ref, err)
		}
		if !strings.HasPrefix(ref, scope) {
			// Refs are not secret, so log the full triple: an operator needs
			// to see exactly what pointed where.
			m.logger.Error("mint descriptor references credentials outside its namespace",
				"token_ref", tokenRef,
				"required_scope", scope,
				"offending_ref", ref,
				"grant_profile", desc.GrantProfile,
			)
			return fmt.Errorf("%w: ref %q is outside %q", ErrDescriptorScopeViolation, ref, scope)
		}
	}
	return nil
}

// fetchSecret reads one credential ref, refusing anything that is not a plain
// stored value.
func (m *MintingTokenStore) fetchSecret(ctx context.Context, ref string) (string, error) {
	entry, err := m.inner.FetchOne(ctx, ref)
	if err != nil {
		return "", err
	}

	// Descriptor chains stop at depth one. Allowing a descriptor to resolve
	// through another descriptor would reintroduce the indirection the scope
	// check exists to bound.
	if entry.Descriptor != nil {
		return "", ErrNestedDescriptor
	}

	if !entry.Passthrough {
		return "", fmt.Errorf("credential must be stored in passthrough mode (minting cannot decrypt KMS ciphertext)")
	}
	if len(entry.EncryptedToken) == 0 {
		return "", fmt.Errorf("credential is empty")
	}
	return string(entry.EncryptedToken), nil
}

// Close releases the inner store.
func (m *MintingTokenStore) Close() error { return m.inner.Close() }

// Sweep drops mint state for credentials nobody has used recently.
func (m *MintingTokenStore) Sweep() int { return m.minter.Sweep() }

// refScope returns the first n path segments of ref, including the trailing
// separator so that HasPrefix cannot match a sibling whose name merely starts
// with the same characters.
func refScope(ref string, n int) (string, error) {
	parts := strings.Split(ref, "/")
	if len(parts) <= n {
		return "", fmt.Errorf("ref has %d path segments, need more than %d to define a credential scope", len(parts), n)
	}
	return strings.Join(parts[:n], "/") + "/", nil
}
