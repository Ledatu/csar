// Package ctxprofile manages named CSAR coordinator connection contexts,
// similar to kubectl's kubeconfig contexts. Contexts are stored in a YAML
// file at ~/.csar/contexts.yaml.
package ctxprofile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Context holds connection details for a coordinator endpoint.
type Context struct {
	// Name is the human-readable identifier for this context.
	Name string `yaml:"name"`

	// Address is the coordinator gRPC address (host:port).
	Address string `yaml:"address"`

	// CAFile is the path to the CA certificate for TLS verification.
	CAFile string `yaml:"ca_file,omitempty"`

	// CertFile is the client certificate for mTLS.
	CertFile string `yaml:"cert_file,omitempty"`

	// KeyFile is the client private key for mTLS.
	KeyFile string `yaml:"key_file,omitempty"`

	// Insecure permits plaintext gRPC (dev only).
	Insecure bool `yaml:"insecure,omitempty"`

	// ConfigPath is the default config.yaml path for this context.
	ConfigPath string `yaml:"config_path,omitempty"`
}

// Store is the on-disk context store.
type Store struct {
	// CurrentContext is the name of the active context.
	CurrentContext string `yaml:"current_context"`

	// Contexts is the list of saved contexts.
	Contexts []Context `yaml:"contexts"`
}

// DefaultStorePath returns ~/.csar/contexts.yaml.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".csar", "contexts.yaml")
	}
	return filepath.Join(home, ".csar", "contexts.yaml")
}

// Load reads the context store from disk. Returns an empty store if the file
// doesn't exist.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{}, nil
		}
		return nil, fmt.Errorf("reading context store: %w", err)
	}

	var store Store
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parsing context store: %w", err)
	}

	return &store, nil
}

// Save writes the store to disk, creating parent directories as needed.
func (s *Store) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshalling context store: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing context store: %w", err)
	}

	return nil
}

// SetContext adds or updates a named context.
func (s *Store) SetContext(ctx Context) {
	for i, existing := range s.Contexts {
		if existing.Name == ctx.Name {
			s.Contexts[i] = ctx
			return
		}
	}
	s.Contexts = append(s.Contexts, ctx)
}

// UseContext sets the active context by name.
// Returns an error if the name doesn't exist.
func (s *Store) UseContext(name string) error {
	for _, ctx := range s.Contexts {
		if ctx.Name == name {
			s.CurrentContext = name
			return nil
		}
	}
	return fmt.Errorf("context %q not found", name)
}

// GetContext returns the named context, or nil if not found.
func (s *Store) GetContext(name string) *Context {
	for i, ctx := range s.Contexts {
		if ctx.Name == name {
			return &s.Contexts[i]
		}
	}
	return nil
}

// ActiveContext returns the current context, or nil if none is set.
func (s *Store) ActiveContext() *Context {
	if s.CurrentContext == "" {
		return nil
	}
	return s.GetContext(s.CurrentContext)
}

// DeleteContext removes a context by name. If it was the active context,
// current_context is cleared.
func (s *Store) DeleteContext(name string) bool {
	for i, ctx := range s.Contexts {
		if ctx.Name == name {
			s.Contexts = append(s.Contexts[:i], s.Contexts[i+1:]...)
			if s.CurrentContext == name {
				s.CurrentContext = ""
			}
			return true
		}
	}
	return false
}

// ContextNames returns a list of all context names.
func (s *Store) ContextNames() []string {
	names := make([]string, len(s.Contexts))
	for i, ctx := range s.Contexts {
		names[i] = ctx.Name
	}
	return names
}
