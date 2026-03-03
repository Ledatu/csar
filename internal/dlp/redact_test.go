package dlp

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRedactor_SimpleField(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"John","email":"john@example.com","age":30}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"email"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	if result["email"] != "***REDACTED***" {
		t.Errorf("email = %v, want redacted", result["email"])
	}
	if result["name"] != "John" {
		t.Errorf("name = %v, want John", result["name"])
	}
	if result["age"] != float64(30) {
		t.Errorf("age = %v, want 30", result["age"])
	}
}

func TestRedactor_NestedField(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"name":"Alice","ssn":"123-45-6789"},"status":"active"}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"user.ssn"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	user := result["user"].(map[string]interface{})
	if user["ssn"] != "***REDACTED***" {
		t.Errorf("user.ssn = %v, want redacted", user["ssn"])
	}
	if user["name"] != "Alice" {
		t.Errorf("user.name = %v, want Alice", user["name"])
	}
}

func TestRedactor_WildcardArray(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"users":[{"name":"Alice","email":"alice@x.com"},{"name":"Bob","email":"bob@x.com"}]}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"users.*.email"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	users := result["users"].([]interface{})
	for i, u := range users {
		user := u.(map[string]interface{})
		if user["email"] != "***REDACTED***" {
			t.Errorf("users[%d].email = %v, want redacted", i, user["email"])
		}
		if user["name"] == "***REDACTED***" {
			t.Errorf("users[%d].name should NOT be redacted", i)
		}
	}
}

func TestRedactor_CustomMask(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"secret":"mysecret"}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"secret"},
		Mask:   "[HIDDEN]",
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	if result["secret"] != "[HIDDEN]" {
		t.Errorf("secret = %v, want [HIDDEN]", result["secret"])
	}
}

func TestRedactor_NonJSON_PassThrough(t *testing.T) {
	expected := "<html>hello</html>"
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(expected))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"email"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != expected {
		t.Errorf("body = %q, want %q (non-JSON should pass through)", string(body), expected)
	}
}

func TestRedactor_NoMatchingFields(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"John"}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"nonexistent"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	if result["name"] != "John" {
		t.Errorf("name = %v, want John (no redaction should occur)", result["name"])
	}
}

func TestRedactor_MultipleFields(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"John","email":"john@x.com","phone":"555-1234","age":30}`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"email", "phone"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	if result["email"] != "***REDACTED***" {
		t.Errorf("email = %v, want redacted", result["email"])
	}
	if result["phone"] != "***REDACTED***" {
		t.Errorf("phone = %v, want redacted", result["phone"])
	}
	if result["name"] != "John" {
		t.Errorf("name = %v, want John", result["name"])
	}
}

func TestRedactor_JSONArray_TopLevel(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"email":"a@x.com"},{"email":"b@x.com"}]`))
	})

	rd := NewRedactor(newTestLogger())
	handler := rd.Wrap(Config{
		Fields: []string{"email"},
	}, upstream)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var result []map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&result)

	for i, item := range result {
		if item["email"] != "***REDACTED***" {
			t.Errorf("[%d].email = %v, want redacted", i, item["email"])
		}
	}
}

func TestRedactPath(t *testing.T) {
	tests := []struct {
		name string
		data interface{}
		path []string
		mask string
		want bool
	}{
		{
			name: "simple field",
			data: map[string]interface{}{"a": "v"},
			path: []string{"a"},
			mask: "X",
			want: true,
		},
		{
			name: "missing field",
			data: map[string]interface{}{"a": "v"},
			path: []string{"b"},
			mask: "X",
			want: false,
		},
		{
			name: "nested",
			data: map[string]interface{}{"a": map[string]interface{}{"b": "v"}},
			path: []string{"a", "b"},
			mask: "X",
			want: true,
		},
		{
			name: "wildcard array",
			data: map[string]interface{}{"items": []interface{}{
				map[string]interface{}{"secret": "s1"},
				map[string]interface{}{"secret": "s2"},
			}},
			path: []string{"items", "*", "secret"},
			mask: "X",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactPath(tt.data, tt.path, tt.mask)
			if got != tt.want {
				t.Errorf("redactPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
