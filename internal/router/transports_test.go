package router

import (
	"net/http"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

func TestTransportRegistry_ReusesSamePoolAndTLS(t *testing.T) {
	reg := newTransportRegistry(map[string]config.BackendPoolConfig{
		"identity-critical": {
			MaxConnsPerHost:       64,
			ResponseHeaderTimeout: config.Duration{Duration: 800 * time.Millisecond},
		},
	}, nil)

	backend := config.BackendConfig{
		TargetURL: "https://authz:9092",
		Pool:      "identity-critical",
		TLS:       &config.BackendTLSConfig{InsecureSkipVerify: true},
	}
	rt1, _, err := reg.forBackend(backend)
	if err != nil {
		t.Fatalf("forBackend #1: %v", err)
	}
	rt2, _, err := reg.forBackend(backend)
	if err != nil {
		t.Fatalf("forBackend #2: %v", err)
	}
	if rt1 != rt2 {
		t.Fatal("expected same transport for same pool/TLS tuple")
	}

	tr, ok := rt1.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", rt1)
	}
	if tr.MaxConnsPerHost != 64 {
		t.Errorf("MaxConnsPerHost = %d, want 64", tr.MaxConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != 800*time.Millisecond {
		t.Errorf("ResponseHeaderTimeout = %s, want 800ms", tr.ResponseHeaderTimeout)
	}
}

func TestTransportRegistry_IsolatesDifferentPools(t *testing.T) {
	reg := newTransportRegistry(map[string]config.BackendPoolConfig{
		"identity-critical": {MaxConnsPerHost: 64},
		"external-wb":       {MaxConnsPerHost: 8},
	}, nil)

	identity, _, err := reg.forBackend(config.BackendConfig{
		TargetURL: "https://authz:9092",
		Pool:      "identity-critical",
	})
	if err != nil {
		t.Fatalf("identity forBackend: %v", err)
	}
	external, _, err := reg.forBackend(config.BackendConfig{
		TargetURL: "https://content-api.wildberries.ru",
		Pool:      "external-wb",
	})
	if err != nil {
		t.Fatalf("external forBackend: %v", err)
	}
	if identity == external {
		t.Fatal("expected different transports for different backend pools")
	}
}
