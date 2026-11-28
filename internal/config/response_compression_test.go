package config

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestResponseCompressionIsExplicitAndValidated(t *testing.T) {
	for _, block := range []string{"", "      x-csar-response-compression:\n        mode: passthrough\n", "      x-csar-response-compression:\n        mode: gzip\n        min_bytes: 4096\n"} {
		body := "listen_addr: ':8080'\npaths:\n  /custom-api:\n    get:\n      x-csar-backend:\n        target_url: https://upstream.example/data\n" + block
		cfg, err := ParseBytes([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if (cfg.Paths["/custom-api"]["get"].ResponseCompression != nil) != (block != "") {
			t.Fatal("missing policy acquired a default")
		}
	}
	for _, p := range []*ResponseCompressionConfig{{}, {Mode: "auto"}, {Mode: "GZIP"}, {Mode: "gzip", MinBytes: -1}, {Mode: "gzip", MinBytes: 65537}, {Mode: "passthrough", MinBytes: 1024}} {
		t.Run(fmt.Sprint(p), func(t *testing.T) {
			cfg := &Config{Paths: map[string]PathConfig{"/arbitrary": {"get": {ResponseCompression: p}}}}
			if cfg.ValidateResponseCompression() == nil {
				t.Fatal("invalid encoding policy accepted")
			}
		})
	}
}

func TestResponseCompressionSchemaMatchesValidation(t *testing.T) {
	data, err := os.ReadFile("../../csar.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var root jsonschema.Schema
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	schema, err := (&jsonschema.Schema{Defs: root.Defs, Ref: "#/$defs/ResponseCompressionConfig"}).Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{`{}`, `{"mode":"passthrough"}`, `{"mode":"gzip"}`, `{"mode":"gzip","min_bytes":0}`, `{"mode":"gzip","min_bytes":65536}`, `{"mode":"gzip","min_bytes":65537}`, `{"mode":"passthrough","min_bytes":1}`, `{"mode":"auto"}`, `{"mode":"gzip","min_bytes":-1}`} {
		var value any
		if err := json.Unmarshal([]byte(sample), &value); err != nil {
			t.Fatal(err)
		}
		var p ResponseCompressionConfig
		if err := json.Unmarshal([]byte(sample), &p); err != nil {
			t.Fatal(err)
		}
		cfg := &Config{Paths: map[string]PathConfig{"/custom": {"get": {ResponseCompression: &p}}}}
		if (schema.Validate(value) == nil) != (cfg.ValidateResponseCompression() == nil) {
			t.Fatalf("schema/runtime disagreement: %s", sample)
		}
	}
}
