package config

import (
	"encoding"
	"reflect"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/logging"
)

// safeExpandEnv delegates to the shared configutil.SafeExpandEnv.
func safeExpandEnv(s string) string {
	return configutil.SafeExpandEnv(s)
}

// expandEnvInStruct delegates to the shared configutil.ExpandEnvInStruct.
func expandEnvInStruct(v reflect.Value) {
	configutil.ExpandEnvInStruct(v)
}

// Compile-time checks.
var (
	_ encoding.TextMarshaler   = logging.Secret{}
	_ encoding.TextUnmarshaler = &logging.Secret{}
	_ configutil.EnvExpandable = &logging.Secret{}
)
