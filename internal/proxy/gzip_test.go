package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeProxyEncodingNegotiation(t *testing.T) {
	payload := []byte(`{"data":"` + strings.Repeat("abc", 1000) + `"}`)
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	_, _ = zw.Write(payload)
	_ = zw.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("upstream gzip negotiation lost")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(packed.Bytes())
	}))
	defer upstream.Close()
	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(rp)
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, explicit := range []bool{true, false} {
		req, _ := http.NewRequest("GET", server.URL, nil)
		if explicit {
			req.Header.Set("Accept-Encoding", "gzip")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if explicit {
			if resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, packed.Bytes()) {
				t.Fatal("proxy changed negotiated compressed bytes")
			}
		} else if resp.Header.Get("Content-Encoding") != "" || !bytes.Equal(body, payload) {
			t.Fatal("proxy implicit transport decoding changed")
		}
	}
}
