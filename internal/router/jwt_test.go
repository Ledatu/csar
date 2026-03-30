package router

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestSetupJWT_UsesValidatorPerJWKSTLSPolicy(t *testing.T) {
	r := &Router{
		cfg: &config.Config{
			BackendTLSPolicies: map[string]config.BackendTLSPolicy{
				"tls-a": {InsecureSkipVerify: true},
				"tls-b": {InsecureSkipVerify: true},
			},
		},
	}

	frA := config.FlatRoute{
		Route: config.RouteConfig{
			AuthValidate: &config.AuthValidateConfig{
				Mode:    "jwt",
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
				JWKSTLS: "tls-a",
			},
		},
	}
	frB := config.FlatRoute{
		Route: config.RouteConfig{
			AuthValidate: &config.AuthValidateConfig{
				Mode:    "jwt",
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
				JWKSTLS: "tls-b",
			},
		},
	}

	rtA1 := &route{}
	if err := r.setupJWT(rtA1, frA, r.cfg, "GET:/svc/a", newTestLogger()); err != nil {
		t.Fatalf("setupJWT route A1: %v", err)
	}

	rtA2 := &route{}
	if err := r.setupJWT(rtA2, frA, r.cfg, "GET:/svc/a2", newTestLogger()); err != nil {
		t.Fatalf("setupJWT route A2: %v", err)
	}

	rtB := &route{}
	if err := r.setupJWT(rtB, frB, r.cfg, "GET:/svc/b", newTestLogger()); err != nil {
		t.Fatalf("setupJWT route B: %v", err)
	}

	if rtA1.jwtValidator == nil || rtA2.jwtValidator == nil || rtB.jwtValidator == nil {
		t.Fatal("expected jwt validators to be assigned")
	}
	if rtA1.jwtValidator != rtA2.jwtValidator {
		t.Fatal("expected same jwks_tls policy to reuse the validator")
	}
	if rtA1.jwtValidator == rtB.jwtValidator {
		t.Fatal("expected different jwks_tls policies to use different validators")
	}
}

func TestSetupJWT_UnknownJWKSTLSPolicyFails(t *testing.T) {
	r := &Router{cfg: &config.Config{}}
	rt := &route{}
	fr := config.FlatRoute{
		Route: config.RouteConfig{
			AuthValidate: &config.AuthValidateConfig{
				Mode:    "jwt",
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
				JWKSTLS: "missing",
			},
		},
	}

	if err := r.setupJWT(rt, fr, r.cfg, "GET:/svc/test", newTestLogger()); err == nil {
		t.Fatal("expected unknown jwks_tls policy to fail")
	}
}
