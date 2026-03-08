package configsource

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashPolicy defines the integrity checking strategy for configs.
type HashPolicy int

const (
	// HashDisabled skips hash validation entirely.
	HashDisabled HashPolicy = iota

	// HashTOFU (Trust On First Use) records the hash on first fetch and
	// detects unexpected content changes when the ETag stays the same.
	// This catches tampering where object metadata is preserved but
	// content is silently replaced.
	HashTOFU

	// HashPinned validates every fetch against an operator-provided
	// SHA-256 hash (--config-sha256 flag). Any mismatch is rejected.
	HashPinned
)

// ComputeSHA256 returns the hex-encoded SHA-256 digest of data.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ValidateHash checks the current hash against the selected policy.
//
// Parameters:
//   - policy: the hash validation strategy
//   - pinnedHash: expected hash for HashPinned (hex-encoded SHA-256)
//   - currentHash: SHA-256 of the just-fetched config data
//   - lastHash: SHA-256 from the previous successful fetch (empty on first run)
//   - currentETag: ETag of the just-fetched config
//   - lastETag: ETag from the previous successful fetch (empty on first run)
//
// Returns an error if hash validation fails, nil otherwise.
func ValidateHash(policy HashPolicy, pinnedHash, currentHash, lastHash, currentETag, lastETag string) error {
	switch policy {
	case HashDisabled:
		return nil

	case HashTOFU:
		// On first fetch (no previous hash), accept and record.
		if lastHash == "" {
			return nil
		}
		// If ETag unchanged but hash changed → content was tampered with.
		if currentETag == lastETag && currentHash != lastHash {
			return fmt.Errorf("config integrity violation: ETag unchanged (%s) but SHA-256 changed (%s → %s); possible tampering",
				currentETag, lastHash, currentHash)
		}
		return nil

	case HashPinned:
		if currentHash != pinnedHash {
			return fmt.Errorf("config SHA-256 mismatch: expected %s, got %s", pinnedHash, currentHash)
		}
		return nil

	default:
		return fmt.Errorf("unknown hash policy: %d", policy)
	}
}
