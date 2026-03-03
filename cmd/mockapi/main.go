// Package main implements a configurable mock upstream API for integration testing.
// It exposes endpoints that echo headers, return configurable status codes,
// simulate delays, and track request counts — everything needed to verify
// CSAR's routing, throttling, circuit breaking, and auth injection.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var requestCount atomic.Int64

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	mux := http.NewServeMux()

	// GET /products — returns a product list, echoes received auth headers
	mux.HandleFunc("GET /products", handleProducts)

	// POST /products — accepts a product, echoes headers
	mux.HandleFunc("POST /products", handleCreateProduct)

	// GET /slow — configurable delay via ?delay=2s query param
	mux.HandleFunc("GET /slow", handleSlow)

	// GET /flaky — returns 500 for the first N requests (N = ?fail_count=3), then 200
	mux.HandleFunc("GET /flaky", handleFlaky)

	// GET /echo-headers — returns all received headers as JSON
	mux.HandleFunc("GET /echo-headers", handleEchoHeaders)

	// GET /health — health check
	mux.HandleFunc("GET /health", handleHealth)

	// GET /stats — request counter
	mux.HandleFunc("GET /stats", handleStats)

	// Catch-all
	mux.HandleFunc("/", handleCatchAll)

	addr := ":" + port
	log.Printf("mockapi starting on %s", addr)
	if err := http.ListenAndServe(addr, countMiddleware(mux)); err != nil {
		log.Fatalf("mockapi: %v", err)
	}
}

func countMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		next.ServeHTTP(w, r)
	})
}

func handleProducts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"products": []map[string]interface{}{
			{"id": 1, "name": "Widget A", "price": 29.99},
			{"id": 2, "name": "Widget B", "price": 49.99},
		},
		"received_auth":    r.Header.Get("Authorization"),
		"received_api_key": r.Header.Get("Api-Key"),
	})
}

func handleCreateProduct(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"created":          true,
		"received_auth":    r.Header.Get("Authorization"),
		"received_api_key": r.Header.Get("Api-Key"),
	})
}

func handleSlow(w http.ResponseWriter, r *http.Request) {
	delayStr := r.URL.Query().Get("delay")
	if delayStr == "" {
		delayStr = "2s"
	}
	delay, err := time.ParseDuration(delayStr)
	if err != nil {
		http.Error(w, fmt.Sprintf("bad delay: %v", err), http.StatusBadRequest)
		return
	}
	time.Sleep(delay)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"delayed": delay.String(),
	})
}

var flakyCounter atomic.Int64

func handleFlaky(w http.ResponseWriter, r *http.Request) {
	failCountStr := r.URL.Query().Get("fail_count")
	failCount := int64(3) // default
	if failCountStr != "" {
		if n, err := strconv.ParseInt(failCountStr, 10, 64); err == nil {
			failCount = n
		}
	}

	count := flakyCounter.Add(1)
	if count <= failCount {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":   "simulated failure",
			"attempt": count,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "recovered",
		"attempt": count,
	})
}

func handleEchoHeaders(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}
	writeJSON(w, http.StatusOK, headers)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "mockapi",
	})
}

func handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_requests": requestCount.Load(),
	})
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"path":   r.URL.Path,
		"method": r.Method,
		"echo":   true,
	})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
