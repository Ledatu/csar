package cache

import (
	"net/http"
	"net/http/httptest"
	"sync"
)

type capturedResponse struct {
	statusCode  int
	headers     http.Header
	body        []byte
	cacheStatus string
}

func captureRecorder(rec *httptest.ResponseRecorder, cacheStatus string) capturedResponse {
	return capturedResponse{
		statusCode:  rec.Code,
		headers:     cloneHeader(rec.Header()),
		body:        append([]byte(nil), rec.Body.Bytes()...),
		cacheStatus: cacheStatus,
	}
}

type coalesceCall struct {
	done   chan struct{}
	result capturedResponse
}

type coalescer struct {
	mu    sync.Mutex
	calls map[string]*coalesceCall
}

func newCoalescer() *coalescer {
	return &coalescer{calls: make(map[string]*coalesceCall)}
}

func (c *coalescer) begin(key string) (bool, *coalesceCall) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if call, ok := c.calls[key]; ok {
		return false, call
	}
	call := &coalesceCall{done: make(chan struct{})}
	c.calls[key] = call
	return true, call
}

func (c *coalescer) finish(key string, call *coalesceCall, result capturedResponse) {
	c.mu.Lock()
	if c.calls[key] == call {
		delete(c.calls, key)
	}
	call.result = result
	close(call.done)
	c.mu.Unlock()
}
