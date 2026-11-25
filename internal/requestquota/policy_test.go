package requestquota

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRequestCaps(t *testing.T) {
	good := Policy{Name: "daily", Key: "scope:{path.cabinet}", Requests: 20, Window: 24 * time.Hour}
	for _, tc := range []struct {
		name   string
		change func(*Policy)
	}{
		{"invalid_name", func(q *Policy) { q.Name = "has space" }},
		{"unbounded_key", func(q *Policy) { q.Key = strings.Repeat("x", 257) }},
		{"negative", func(q *Policy) { q.Requests = -1 }},
		{"oversized", func(q *Policy) { q.Requests = 10001 }},
		{"short_window", func(q *Policy) { q.Window = time.Millisecond }},
		{"long_window", func(q *Policy) { q.Window = 25 * time.Hour }},
		{"submillisecond_precision", func(q *Policy) { q.Window = time.Second + time.Nanosecond }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := good
			tc.change(&q)
			if Validate([]Policy{q}) == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
	if err := Validate([]Policy{good}); err != nil {
		t.Fatal(err)
	}
	closed := good
	closed.Requests = 0
	if err := Validate([]Policy{closed}); err != nil {
		t.Fatal("closed policy rejected", err)
	}
	if Validate([]Policy{good, good}) == nil {
		t.Fatal("duplicate names accepted")
	}
	other := good
	other.Name = "minute"
	other.Key = "other-scope"
	if Validate([]Policy{good, other}) == nil {
		t.Fatal("different scopes cannot share atomic admission")
	}
}
