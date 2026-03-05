package config

import (
	"encoding"
	"os"
	"reflect"

	"github.com/ledatu/csar/internal/logging"
)

// safeExpandEnv expands ${VAR} and $VAR references to environment variables,
// but preserves bare numeric references ($1, $2, ${1}, etc.) which are regex
// back-references in path_rewrite rules.
//
// POSIX environment variable names never start with a digit, so any variable
// reference whose name begins with 0-9 is a back-reference, not an env var.
func safeExpandEnv(s string) string {
	return os.Expand(s, func(key string) string {
		if len(key) == 0 {
			return ""
		}
		// Skip keys that start with a digit — these are regex
		// back-references ($1, $2, …), not environment variables.
		if key[0] >= '0' && key[0] <= '9' {
			return "$" + key
		}
		return os.Getenv(key)
	})
}

// expandEnvInStruct recursively walks a struct value and expands environment
// variable references (${VAR}, $VAR) in all string fields.
//
// This is YAML-injection-safe: expansion happens after YAML unmarshaling, so
// an env var value containing YAML control characters (quotes, newlines,
// colons) cannot alter the parsed configuration structure.
//
// Supported types:
//   - string fields: expanded directly via safeExpandEnv.
//   - Types implementing encoding.TextMarshaler + encoding.TextUnmarshaler
//     (e.g. logging.Secret): expanded through those interfaces.
//   - map[K]V: values are recursively expanded (keys are left as-is).
//   - []T: elements are recursively expanded.
//   - Nested structs and pointers: recursed into.
//   - Non-string primitives (bool, int, float, etc.): skipped.
func expandEnvInStruct(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			expandEnvInStruct(v.Elem())
		}

	case reflect.Struct:
		// Types implementing TextMarshaler + TextUnmarshaler (e.g. logging.Secret)
		// are expanded through those interfaces instead of recursing into fields.
		if v.CanAddr() {
			ptr := v.Addr().Interface()
			tm, isTM := ptr.(encoding.TextMarshaler)
			tu, isTU := ptr.(encoding.TextUnmarshaler)
			if isTM && isTU {
				text, err := tm.MarshalText()
				if err == nil && len(text) > 0 {
					expanded := safeExpandEnv(string(text))
					if expanded != string(text) {
						_ = tu.UnmarshalText([]byte(expanded))
					}
				}
				return
			}
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.CanSet() {
				expandEnvInStruct(f)
			}
		}

	case reflect.String:
		if v.CanSet() {
			expanded := safeExpandEnv(v.String())
			if expanded != v.String() {
				v.SetString(expanded)
			}
		}

	case reflect.Map:
		if v.IsNil() {
			return
		}
		keys := v.MapKeys()
		for _, key := range keys {
			origVal := v.MapIndex(key)
			// Map values are not addressable — copy to a settable location,
			// expand, and write back.
			cp := reflect.New(origVal.Type()).Elem()
			cp.Set(origVal)
			expandEnvInStruct(cp)
			v.SetMapIndex(key, cp)
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			expandEnvInStruct(v.Index(i))
		}
	}
}

// Compile-time check: ensure logging.Secret is handled via text interfaces.
var (
	_ encoding.TextMarshaler   = logging.Secret{}
	_ encoding.TextUnmarshaler = &logging.Secret{}
)
