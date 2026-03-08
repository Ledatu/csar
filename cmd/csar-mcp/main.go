// Command csar-mcp exposes CSAR config tooling as an MCP (Model Context
// Protocol) server so that AI agents can create, validate, inspect, and
// simulate CSAR gateway configurations.
//
// Transport: stdio (newline-delimited JSON over stdin/stdout).
//
// Tools provided:
//
//	validate_config  — validate a config.yaml from raw YAML text
//	inspect_config   — resolve includes/policies and return the final config as JSON
//	simulate_route   — dry-run route matching for a given method + path
//	scaffold_config  — generate starter files for a deployment profile
//	list_profiles    — list available deployment profiles
//	get_schema       — return the csar.schema.json for IDE / agent autocomplete
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/helper"
	"github.com/ledatu/csar/internal/simulate"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed schema.json
var schemaJSON string

// ─── Tool input types ───────────────────────────────────────────────────────

type ValidateInput struct {
	YAML string `json:"yaml" jsonschema:"the full config.yaml content to validate"`
}

type InspectInput struct {
	YAML  string `json:"yaml" jsonschema:"the full config.yaml content to inspect"`
	Route string `json:"route,omitempty" jsonschema:"optional route filter, e.g. GET /api/v1/users"`
}

type SimulateInput struct {
	YAML   string `json:"yaml" jsonschema:"the full config.yaml content"`
	Path   string `json:"path" jsonschema:"request path to simulate, e.g. /api/users"`
	Method string `json:"method" jsonschema:"HTTP method, e.g. GET, POST"`
}

type ScaffoldInput struct {
	Profile string `json:"profile" jsonschema:"deployment profile: dev-local, prod-single, or prod-distributed"`
}

// ─── Handlers ───────────────────────────────────────────────────────────────

func handleValidate(_ context.Context, _ *mcp.CallToolRequest, in ValidateInput) (*mcp.CallToolResult, any, error) {
	_, err := config.ParseBytes([]byte(in.YAML))
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("validation failed: %v", err)}},
			IsError: true,
		}, nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "config is valid"}},
	}, nil, nil
}

func handleInspect(_ context.Context, _ *mcp.CallToolRequest, in InspectInput) (*mcp.CallToolResult, any, error) {
	cfg, err := config.ParseBytes([]byte(in.YAML))
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("parse error: %v", err)}},
			IsError: true,
		}, nil, nil
	}

	var target any = cfg

	if in.Route != "" {
		parts := strings.SplitN(in.Route, " ", 2)
		if len(parts) != 2 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "route must be \"METHOD /path\" (e.g. \"GET /api/v1/users\")"}},
				IsError: true,
			}, nil, nil
		}
		method := strings.ToLower(strings.TrimSpace(parts[0]))
		path := strings.TrimSpace(parts[1])

		methods, ok := cfg.Paths[path]
		if !ok {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("path %q not found in config", path)}},
				IsError: true,
			}, nil, nil
		}
		route, ok := methods[method]
		if !ok {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("method %q not found for path %q", strings.ToUpper(method), path)}},
				IsError: true,
			}, nil, nil
		}
		target = route
	}

	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling config: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func handleSimulate(_ context.Context, _ *mcp.CallToolRequest, in SimulateInput) (*mcp.CallToolResult, any, error) {
	cfg, err := config.ParseBytes([]byte(in.YAML))
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("parse error: %v", err)}},
			IsError: true,
		}, nil, nil
	}

	result := simulate.Simulate(cfg, simulate.Request{
		Path:   in.Path,
		Method: in.Method,
	})

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling result: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func handleScaffold(_ context.Context, _ *mcp.CallToolRequest, in ScaffoldInput) (*mcp.CallToolResult, any, error) {
	if !helper.IsValidProfile(in.Profile) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("unknown profile %q; valid profiles: %v", in.Profile, helper.ValidProfiles())}},
			IsError: true,
		}, nil, nil
	}

	tmpDir, err := os.MkdirTemp("", "csar-scaffold-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := helper.InitProfile(helper.Profile(in.Profile), tmpDir, true); err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("scaffold error: %v", err)}},
			IsError: true,
		}, nil, nil
	}

	// Walk the temp dir and collect all generated files.
	files := make(map[string]string)
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(tmpDir, path)
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files[rel] = string(content)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("reading scaffold output: %w", err)
	}

	data, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling files: %w", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, nil, nil
}

func handleListProfiles(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
	profiles := helper.ValidProfiles()
	lines := make([]string, len(profiles))
	for i, p := range profiles {
		lines[i] = string(p)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(lines, "\n")}},
	}, nil, nil
}

func handleGetSchema(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: schemaJSON}},
	}, nil, nil
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "csar-mcp", Version: "v1.0.0"},
		nil,
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "validate_config",
		Description: "Validate a CSAR config.yaml. Returns OK or a list of errors.",
	}, handleValidate)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "inspect_config",
		Description: "Parse a CSAR config.yaml through the full include/merge/resolve pipeline and return the resolved config as JSON. Optionally filter to a single route.",
	}, handleInspect)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "simulate_route",
		Description: "Simulate request routing against a CSAR config. Shows which route matches, target URL, match type, and the full middleware pipeline. No real network requests are made.",
	}, handleSimulate)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scaffold_config",
		Description: "Generate starter config files (config.yaml, .env.example, etc.) for a given deployment profile. Returns a JSON map of filename to file content.",
	}, handleScaffold)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_profiles",
		Description: "List available CSAR deployment profiles (dev-local, prod-single, prod-distributed).",
	}, handleListProfiles)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_schema",
		Description: "Return the csar.schema.json JSON Schema for config.yaml. Useful for understanding all available fields, types, and constraints.",
	}, handleGetSchema)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
