package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ledatu/csar/internal/logging"
	"gopkg.in/yaml.v3"
)

func TestRestartRequiredSettings(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"profile", "prod-distributed"}, {"listen_addr", "':8443'"},
		{"tls.cert_file", "server.pem"}, {"tls.key_file", "server.key"},
		{"tls.client_ca_file", "ca.pem"}, {"tls.min_version", "'1.3'"},
		{"security_policy.environment", "prod"},
		{"security_policy.forbid_insecure_in_prod", "true"},
		{"security_policy.require_mtls_for_coordinator", "true"},
		{"security_policy.redact_sensitive_logs", "true"},
		{"kms.provider", "yandexapi"}, {"kms.default_key_id", "key-id"},
		{"kms.operation_timeout", "5s"}, {"kms.local_keys", "{test-key: test-passphrase}"},
		{"kms.retry.max_attempts", "3"}, {"kms.retry.base_delay", "1s"},
		{"kms.retry.max_delay", "10s"}, {"kms.retry.jitter", "true"},
		{"kms.cache.enabled", "true"}, {"kms.cache.ttl", "1m"}, {"kms.cache.max_entries", "100"},
		{"kms.yandex.endpoint", "https://kms.example"}, {"kms.yandex.auth_mode", "metadata"},
		{"kms.yandex.iam_token", "test-iam"}, {"kms.yandex.oauth_token", "test-oauth"},
		{"kms.yandex.sa_key_file", "sa.json"},
		{"coordinator.enabled", "true"}, {"coordinator.address", "coordinator:9090"},
		{"coordinator.discovery_method", "dns"}, {"coordinator.ca_file", "ca.pem"},
		{"coordinator.cert_file", "client.pem"}, {"coordinator.key_file", "client.key"},
		{"coordinator.allow_insecure", "true"}, {"coordinator.invalidation_buffer_size", "200"},
		{"redis.address", "redis:6379"}, {"redis.password", "test-password"}, {"redis.db", "3"},
		{"readiness.enabled", "true"}, {"readiness.path", "/ready"}, {"readiness.include_details", "false"},
		{"authz.address", "authz:9091"}, {"authz.ca_file", "ca.pem"},
		{"authz.cert_file", "client.pem"}, {"authz.key_file", "client.key"},
		{"authz.allow_insecure", "true"}, {"authz.timeout", "1s"},
		{"audit.address", "audit:9092"}, {"audit.ca_file", "ca.pem"},
		{"audit.cert_file", "client.pem"}, {"audit.key_file", "client.key"},
		{"audit.allow_insecure", "true"}, {"audit.timeout", "1s"},
		{"origin_issuer.endpoint", "https://issuer.example/root"},
		{"origin_issuer.issuer", "https://issuer.example"},
		{"origin_issuer.jwks_url", "https://issuer.example/jwks"},
		{"origin_issuer.tls.ca_file", "issuer-ca.pem"},
		{"origin_issuer.tls.cert_file", "router.pem"},
		{"origin_issuer.tls.key_file", "router.key"},
		{"origin_issuer.tls.insecure_skip_verify", "true"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			var data strings.Builder
			parts := strings.Split(tc.field, ".")
			for i, part := range parts {
				data.WriteString(strings.Repeat("  ", i) + part + ":")
				if i == len(parts)-1 {
					data.WriteString(" " + tc.value)
				}
				data.WriteString("\n")
			}
			var changed Config
			if err := yaml.Unmarshal([]byte(data.String()), &changed); err != nil {
				t.Fatal(err)
			}
			empty := &Config{}
			for _, pair := range [][2]*Config{{empty, &changed}, {&changed, empty}} {
				got := SnapshotRestartRequired(pair[0]).Changes(pair[1])
				if !reflect.DeepEqual(got, []string{tc.field}) {
					t.Fatalf("changed fields = %v, want [%s]", got, tc.field)
				}
			}
		})
	}
}

func TestRestartSnapshotDoesNotAliasSecrets(t *testing.T) {
	cfg := &Config{
		Redis: &RedisConfig{Password: logging.NewSecret("old-password")},
		KMS: &KMSConfig{
			LocalKeys: map[string]string{"key": "old-passphrase"},
			Yandex:    &YandexKMSConfig{IAMToken: logging.NewSecret("old-iam")},
		},
	}
	snap := SnapshotRestartRequired(cfg)
	cfg.Redis.Password = logging.NewSecret("new-password")
	cfg.KMS.LocalKeys["key"] = "new-passphrase"
	cfg.KMS.Yandex.IAMToken = logging.NewSecret("new-iam")
	if got, want := snap.Changes(cfg), []string{"kms.local_keys", "kms.yandex.iam_token", "redis.password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changed secret fields = %v, want %v", got, want)
	}
}

func TestRestartSnapshotIgnoresHotSettings(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(`redis:
  key_prefix: 'custom:'
audit:
  capture:
    response: off
    max_bytes: 1024
ssrf_protection:
  allowed_internal_hosts: [user-preferences]
global_throttle:
  rate: 10
  burst: 20
debug_headers:
  enabled: true
paths:
  /test:
    get:
      x-csar-backend:
        target_url: https://upstream.example
`), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := SnapshotRestartRequired(&Config{}).Changes(&cfg); len(got) != 0 {
		t.Fatalf("hot settings require restart: %v", got)
	}
	if got := (RestartRequiredSnapshot{}).Changes(&cfg); len(got) != 0 {
		t.Fatalf("initial coordinator load requires restart: %v", got)
	}
}
