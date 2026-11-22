package config

import (
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/ledatu/csar/internal/logging"
)

// RestartRequiredSnapshot captures startup settings independently of the source
// config. Changes returns field names only, including when secrets change.
type RestartRequiredSnapshot struct {
	fields map[string]any
}

func SnapshotRestartRequired(cfg *Config) RestartRequiredSnapshot {
	if cfg == nil {
		cfg = &Config{}
	}
	s := RestartRequiredSnapshot{fields: make(map[string]any)}
	v := reflect.ValueOf(cfg).Elem()
	for i := range v.NumField() {
		name := strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0]
		switch name {
		case "profile", "listen_addr", "tls", "security_policy", "kms",
			"coordinator", "redis", "readiness", "authz", "audit", "origin_issuer":
			s.capture(name, v.Field(i))
		}
	}
	return s
}

func (s RestartRequiredSnapshot) capture(path string, v reflect.Value) {
	if path == "redis.key_prefix" || path == "audit.capture" {
		return
	}
	if v.Kind() == reflect.Pointer {
		if v.Type().Elem().Kind() != reflect.Struct {
			var value any
			if !v.IsNil() {
				value = v.Elem().Interface()
			}
			s.fields[path] = value
			return
		}
		if v.IsNil() {
			v = reflect.Zero(v.Type().Elem())
		} else {
			v = v.Elem()
		}
	}
	switch value := v.Interface().(type) {
	case logging.Secret, Duration:
		s.fields[path] = value
	case map[string]string:
		// Local KMS passphrase maps must not remain aliased to the caller.
		s.fields[path] = maps.Clone(value)
	default:
		if v.Kind() == reflect.Struct {
			for i := range v.NumField() {
				name := strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0]
				s.capture(path+"."+name, v.Field(i))
			}
		} else {
			s.fields[path] = value
		}
	}
}

// Changes compares against the immutable snapshot. A zero snapshot has no
// baseline yet, as during the coordinator's initial config load.
func (s RestartRequiredSnapshot) Changes(cfg *Config) []string {
	if s.fields == nil {
		return nil
	}
	current := SnapshotRestartRequired(cfg)
	var changed []string
	for name, value := range s.fields {
		if !reflect.DeepEqual(value, current.fields[name]) {
			changed = append(changed, name)
		}
	}
	slices.Sort(changed)
	return changed
}
