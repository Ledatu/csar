package config

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestSchemaParity verifies that every property in csar.schema.json's top-level
// "properties" has a corresponding field in the Config Go struct (matched by
// JSON tag), and vice versa.
//
// This catches schema-vs-runtime drift: documented fields that runtime ignores,
// or runtime fields missing from the schema.
func TestSchemaParity(t *testing.T) {
	schemaPath := "../../csar.schema.json"
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Skipf("schema file not found at %s (run test from csar root): %v", schemaPath, err)
	}

	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parsing schema: %v", err)
	}

	goFields := extractJSONTags(reflect.TypeOf(Config{}))

	// Fields intentionally excluded from parity (non-serialized runtime fields).
	excluded := map[string]bool{
		"warnings": true, // yaml:"-" — not in schema
	}

	// Check: every schema property should exist in Go struct.
	for prop := range schema.Properties {
		if excluded[prop] {
			continue
		}
		if _, ok := goFields[prop]; !ok {
			t.Errorf("schema property %q has no matching Go struct field (json tag)", prop)
		}
	}

	// Check: every Go JSON-tagged field should exist in schema.
	for tag := range goFields {
		if excluded[tag] {
			continue
		}
		if _, ok := schema.Properties[tag]; !ok {
			t.Errorf("Go Config field with json tag %q has no matching schema property", tag)
		}
	}
}

// extractJSONTags returns a set of json field names for a struct type.
// Skips fields with json:"-".
func extractJSONTags(t reflect.Type) map[string]bool {
	result := make(map[string]bool)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			result[name] = true
		}
	}
	return result
}
