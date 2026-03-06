package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// loader handles recursive config file loading with cycle detection
// and deduplication. Files are loaded in include-order and merged
// into a single Config.
type loader struct {
	registry map[string]*Config // abs path → parsed config (dedup)
	stack    []string           // abs paths for cycle detection
}

// loadRoot loads the root config file and recursively processes all includes.
// Returns the fully-merged Config (before env expansion and policy resolution).
func (l *loader) loadRoot(path string) (*Config, error) {
	cfg, err := l.load(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// load reads a single config file, recursively loads its includes,
// and returns the merged result.
func (l *loader) load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path %s: %w", path, err)
	}

	// Cycle detection.
	for _, p := range l.stack {
		if p == abs {
			return nil, fmt.Errorf("config include cycle detected: %s → %s",
				strings.Join(l.stack, " → "), abs)
		}
	}

	// Dedup: return cached result if already parsed.
	if cached, ok := l.registry[abs]; ok {
		return cached, nil
	}

	l.stack = append(l.stack, abs)
	defer func() { l.stack = l.stack[:len(l.stack)-1] }()

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", abs, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", abs, err)
	}

	// Capture source metadata from yaml.Node for route fields.
	captureSourceMeta(data, abs, cfg)

	// Process includes: resolve relative paths and globs.
	baseDir := filepath.Dir(abs)
	for _, pattern := range cfg.Include {
		resolved := pattern
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(baseDir, resolved)
		}

		matches, err := filepath.Glob(resolved)
		if err != nil {
			return nil, fmt.Errorf("include glob %q in %s: %w", pattern, abs, err)
		}
		if len(matches) == 0 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("include pattern %q in %s matched no files", pattern, abs))
			continue
		}

		// Sort for deterministic merge order.
		sort.Strings(matches)

		for _, match := range matches {
			child, err := l.load(match)
			if err != nil {
				return nil, err
			}
			if err := mergeConfigs(cfg, child, match); err != nil {
				return nil, err
			}
		}
	}

	// Clear includes after processing — they're fully merged now.
	cfg.Include = nil

	l.registry[abs] = cfg
	return cfg, nil
}

// captureSourceMeta parses YAML as a Node tree and annotates RouteConfig.SourceInfo
// with file and line information for each x-csar-* field.
func captureSourceMeta(data []byte, file string, cfg *Config) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return // best-effort; config already parsed successfully
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}

	// Find the "paths" key in the root mapping.
	pathsNode := findMapValue(root, "paths")
	if pathsNode == nil || pathsNode.Kind != yaml.MappingNode {
		return
	}

	// Iterate paths: key=path, value=methods mapping
	for i := 0; i+1 < len(pathsNode.Content); i += 2 {
		pathKey := pathsNode.Content[i].Value
		methodsNode := pathsNode.Content[i+1]
		if methodsNode.Kind != yaml.MappingNode {
			continue
		}

		// Iterate methods: key=method, value=route mapping
		for j := 0; j+1 < len(methodsNode.Content); j += 2 {
			methodKey := methodsNode.Content[j].Value
			routeNode := methodsNode.Content[j+1]
			if routeNode.Kind != yaml.MappingNode {
				continue
			}

			// Find and update the matching RouteConfig.
			methods, ok := cfg.Paths[pathKey]
			if !ok {
				continue
			}
			route, ok := methods[methodKey]
			if !ok {
				continue
			}
			if route.SourceInfo == nil {
				route.SourceInfo = make(map[string]SourceMeta)
			}

			// Record line numbers for each x-csar-* field in the route.
			for k := 0; k+1 < len(routeNode.Content); k += 2 {
				fieldName := routeNode.Content[k].Value
				fieldNode := routeNode.Content[k+1]
				route.SourceInfo[fieldName] = SourceMeta{
					File: file,
					Line: fieldNode.Line,
				}
			}

			methods[methodKey] = route
		}
	}
}

// annotatePolicy records that a route field was inherited from a named policy.
func annotatePolicy(route *RouteConfig, field, policyName string) {
	if route.SourceInfo == nil {
		route.SourceInfo = make(map[string]SourceMeta)
	}
	meta := route.SourceInfo[field]
	meta.Policy = policyName
	route.SourceInfo[field] = meta
}

// findMapValue returns the value node for a given key in a yaml.MappingNode.
func findMapValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
