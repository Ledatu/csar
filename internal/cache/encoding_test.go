package cache

import (
	"net/http/httptest"
	"testing"
)

func TestEncodingRepresentationsHaveDistinctKeys(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		seen := map[string]bool{}
		for _, encoding := range []string{"", "identity", "gzip", "br"} {
			r := httptest.NewRequest(method, "/data", nil)
			if encoding != "" {
				r.Header.Set("Accept-Encoding", encoding)
			}
			key, err := BuildCacheKey("data", "", nil, nil, nil, r, "body-digest")
			if err != nil {
				t.Fatal(err)
			}
			if seen[key] {
				t.Fatalf("%s encoding %q aliases a different representation", method, encoding)
			}
			seen[key] = true
		}
	}
}

func TestEncodingKeysIncludeAllHeaderLines(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		a := httptest.NewRequest(method, "/", nil)
		a.Header.Add("Accept-Encoding", "br")
		a.Header.Add("Accept-Encoding", "gzip")
		b := httptest.NewRequest(method, "/", nil)
		b.Header.Add("Accept-Encoding", "br")
		b.Header.Add("Accept-Encoding", "identity")
		ka, err := BuildCacheKey("data", "", nil, nil, nil, a, "digest")
		if err != nil {
			t.Fatal(err)
		}
		kb, err := BuildCacheKey("data", "", nil, nil, nil, b, "digest")
		if err != nil {
			t.Fatal(err)
		}
		if ka == kb {
			t.Fatal("second encoding line ignored")
		}
	}
}
