package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/ledatu/csar/internal/logging"
	"gopkg.in/yaml.v3"
)

// Compile flattens a config file and its includes into a single document that
// ParseBytes can load from a remote config source.
//
// Environment references are left unexpanded: they belong to the process that
// loads the compiled document, not to the machine that compiles it. Secret
// fields are written with their source text, since their marshaled form is
// always redacted.
func Compile(path string) ([]byte, error) {
	if _, err := Load(path); err != nil {
		return nil, err
	}

	l := &loader{registry: make(map[string]*Config)}
	cfg, err := l.loadRoot(path)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.ResolvePolicies(); err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := root.Encode(cfg); err != nil {
		return nil, fmt.Errorf("encoding compiled config: %w", err)
	}

	var secrets []secretSource
	collectSecretSources(reflect.ValueOf(cfg), nil, &secrets)
	for _, s := range secrets {
		if err := setScalar(&root, s.path, s.text); err != nil {
			return nil, fmt.Errorf("writing secret %s: %w", strings.Join(s.path, "."), err)
		}
	}

	return yaml.Marshal(&root)
}

type secretSource struct {
	path []string
	text string
}

func collectSecretSources(v reflect.Value, path []string, out *[]secretSource) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			collectSecretSources(v.Elem(), path, out)
		}
	case reflect.Struct:
		if secret, ok := v.Interface().(logging.Secret); ok {
			if text := secret.ExpandableValue(); text != "" {
				*out = append(*out, secretSource{path: append([]string(nil), path...), text: text})
			}
			return
		}
		t := v.Type()
		for i := range t.NumField() {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name)
			}
			collectSecretSources(v.Field(i), append(path, name), out)
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return
		}
		iter := v.MapRange()
		for iter.Next() {
			collectSecretSources(iter.Value(), append(path, iter.Key().String()), out)
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			collectSecretSources(v.Index(i), append(path, strconv.Itoa(i)), out)
		}
	}
}

func setScalar(node *yaml.Node, path []string, value string) error {
	for i, key := range path {
		last := i == len(path)-1
		switch node.Kind {
		case yaml.MappingNode:
			child := findMapValue(node, key)
			if child == nil {
				child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
			}
			if last {
				*child = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
				return nil
			}
			node = child
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(node.Content) {
				return fmt.Errorf("sequence index %q out of range", key)
			}
			if last {
				*node.Content[idx] = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
				return nil
			}
			node = node.Content[idx]
		default:
			return fmt.Errorf("cannot descend into %q", key)
		}
	}
	return nil
}
