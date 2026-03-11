package throttle

import (
	"net/http"
	"net/url"
	"testing"
)

func TestResolveKey_QueryParam(t *testing.T) {
	dt := NewDynamicThrottler(nil, "csar:rl:", "seller:{query.seller_id}", 10, 20, 0)

	req := &http.Request{
		URL: &url.URL{
			RawQuery: "seller_id=abc123&other=val",
		},
		Header: http.Header{},
	}

	got := dt.resolveKey(req)
	want := "seller:abc123"
	if got != want {
		t.Errorf("resolveKey() = %q, want %q", got, want)
	}
}

func TestResolveKey_HeaderParam(t *testing.T) {
	dt := NewDynamicThrottler(nil, "csar:rl:", "api:{header.X-API-Key}", 10, 20, 0)

	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{"X-Api-Key": []string{"my-key-456"}},
	}

	got := dt.resolveKey(req)
	want := "api:my-key-456"
	if got != want {
		t.Errorf("resolveKey() = %q, want %q", got, want)
	}
}

func TestResolveKey_Composite(t *testing.T) {
	dt := NewDynamicThrottler(nil, "", "user:{query.user_id}:{header.X-Tenant}", 10, 20, 0)

	req := &http.Request{
		URL:    &url.URL{RawQuery: "user_id=u42"},
		Header: http.Header{"X-Tenant": []string{"acme"}},
	}

	got := dt.resolveKey(req)
	want := "user:u42:acme"
	if got != want {
		t.Errorf("resolveKey() = %q, want %q", got, want)
	}
}

func TestResolveKey_MissingParam(t *testing.T) {
	dt := NewDynamicThrottler(nil, "", "seller:{query.seller_id}", 10, 20, 0)

	req := &http.Request{
		URL:    &url.URL{},
		Header: http.Header{},
	}

	got := dt.resolveKey(req)
	want := "seller:_unknown_"
	if got != want {
		t.Errorf("resolveKey() = %q, want %q", got, want)
	}
}

func TestResolveKey_NilRequest(t *testing.T) {
	dt := NewDynamicThrottler(nil, "", "seller:{query.seller_id}", 10, 20, 0)

	got := dt.resolveKey(nil)
	want := "seller:{query.seller_id}"
	if got != want {
		t.Errorf("resolveKey(nil) = %q, want %q", got, want)
	}
}

func TestSanitizeKeyPart(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123", "abc123"},
		{"abc-def_ghi.jkl:mno", "abc-def_ghi.jkl:mno"},
		{"abc/def", "abcdef"},                 // slashes removed
		{"abc def", "abcdef"},                 // spaces removed
		{"abc{def}", "abcdef"},                // braces removed
		{"a" + string(make([]byte, 200)), ""}, // long string truncated
	}

	for _, tt := range tests {
		got := sanitizeKeyPart(tt.input)
		if len(tt.input) > 128 && len(got) > 128 {
			t.Errorf("sanitizeKeyPart(%q) length = %d, want <= 128", tt.input[:20], len(got))
		}
		if len(tt.input) <= 128 && got != tt.want {
			t.Errorf("sanitizeKeyPart(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractKeyPlaceholders(t *testing.T) {
	tests := []struct {
		template string
		want     int
	}{
		{"seller:{query.seller_id}", 1},
		{"user:{query.user_id}:{header.X-Tenant}", 2},
		{"no-placeholders", 0},
		{"{query.a}:{query.b}:{header.c}", 3},
	}

	for _, tt := range tests {
		got := ExtractKeyPlaceholders(tt.template)
		if len(got) != tt.want {
			t.Errorf("ExtractKeyPlaceholders(%q) = %v (len %d), want len %d", tt.template, got, len(got), tt.want)
		}
	}
}

func TestWithRequestAndRequestFromContext(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com?seller_id=42", nil)
	ctx := WithRequest(req.Context(), req)

	got := requestFromContext(ctx)
	if got != req {
		t.Error("requestFromContext should return the same request")
	}

	// Without request in context
	got2 := requestFromContext(req.Context())
	if got2 != nil {
		t.Error("requestFromContext without WithRequest should return nil")
	}
}
