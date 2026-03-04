package helper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLSourceConfig configures the YAML/JSON source adapter.
type YAMLSourceConfig struct {
	File string // path to YAML or JSON file
}

// YAMLSource reads tokens from a YAML or JSON file.
// Supported formats:
//
//	Map format:      { "token_ref": "plaintext_value", ... }
//	Array format:    [ { "token_ref": "ref", "token": "value" }, ... ]
//	Detailed format: { "token_ref": { "token": "value", "kms_key_id": "key" }, ... }
type YAMLSource struct {
	cfg YAMLSourceConfig
}

// NewYAMLSource creates a new YAML/JSON source adapter.
func NewYAMLSource(cfg YAMLSourceConfig) *YAMLSource {
	return &YAMLSource{cfg: cfg}
}

// Load reads and parses the YAML/JSON file into tokens.
func (s *YAMLSource) Load(_ context.Context) (map[string]TokenData, error) {
	data, err := os.ReadFile(s.cfg.File)
	if err != nil {
		return nil, fmt.Errorf("yaml source: reading file: %w", err)
	}

	// Detect format by extension
	ext := strings.ToLower(filepath.Ext(s.cfg.File))
	isJSON := ext == ".json"

	// Try map[string]string first (simplest: {ref: plaintext})
	var simpleMap map[string]string
	if isJSON {
		err = json.Unmarshal(data, &simpleMap)
	} else {
		err = yaml.Unmarshal(data, &simpleMap)
	}
	if err == nil && len(simpleMap) > 0 {
		result := make(map[string]TokenData, len(simpleMap))
		for ref, token := range simpleMap {
			result[ref] = TokenData{Plaintext: token}
		}
		return result, nil
	}

	// Try map[string]detailedEntry (ref -> {token, kms_key_id})
	type detailedEntry struct {
		Token    string `yaml:"token" json:"token"`
		KMSKeyID string `yaml:"kms_key_id" json:"kms_key_id"`
	}
	var detailedMap map[string]detailedEntry
	if isJSON {
		err = json.Unmarshal(data, &detailedMap)
	} else {
		err = yaml.Unmarshal(data, &detailedMap)
	}
	if err == nil && len(detailedMap) > 0 {
		result := make(map[string]TokenData, len(detailedMap))
		for ref, entry := range detailedMap {
			if entry.KMSKeyID != "" {
				// Encrypted tokens are stored as base64 (the output of `token encrypt`).
				// Decode to raw ciphertext bytes before storing.
				encBytes, decErr := base64.StdEncoding.DecodeString(entry.Token)
				if decErr != nil {
					return nil, fmt.Errorf("yaml source: token %q has kms_key_id but token value is not valid base64: %w", ref, decErr)
				}
				result[ref] = TokenData{
					EncryptedToken: encBytes,
					KMSKeyID:       entry.KMSKeyID,
				}
			} else {
				result[ref] = TokenData{Plaintext: entry.Token}
			}
		}
		return result, nil
	}

	// Try array format: [{token_ref, token}, ...]
	type arrayEntry struct {
		TokenRef string `yaml:"token_ref" json:"token_ref"`
		Token    string `yaml:"token" json:"token"`
		KMSKeyID string `yaml:"kms_key_id" json:"kms_key_id"`
	}
	var arrayData []arrayEntry
	if isJSON {
		err = json.Unmarshal(data, &arrayData)
	} else {
		err = yaml.Unmarshal(data, &arrayData)
	}
	if err == nil && len(arrayData) > 0 {
		result := make(map[string]TokenData, len(arrayData))
		for _, entry := range arrayData {
			if entry.TokenRef == "" {
				continue
			}
			if entry.KMSKeyID != "" {
				encBytes, decErr := base64.StdEncoding.DecodeString(entry.Token)
				if decErr != nil {
					return nil, fmt.Errorf("yaml source: token %q has kms_key_id but token value is not valid base64: %w", entry.TokenRef, decErr)
				}
				result[entry.TokenRef] = TokenData{
					EncryptedToken: encBytes,
					KMSKeyID:       entry.KMSKeyID,
				}
			} else {
				result[entry.TokenRef] = TokenData{Plaintext: entry.Token}
			}
		}
		return result, nil
	}

	return nil, fmt.Errorf("yaml source: could not parse file %q — expected map (ref->token), map (ref->{token,kms_key_id}), or array of {token_ref, token}", s.cfg.File)
}
