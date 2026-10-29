package cache

import (
	"net/http"
	"net/http/httptest"

	"github.com/ledatu/csar-core/readcache"
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

// Limits apply per ResponseCache instance, across its routes. Overload is
// rejected, never converted into a second uncoalesced upstream request.
const maxCoalesceKeys = 1024
const maxCoalesceFollowers = 128
const maxCoalesceKeyBytes = 4096

func newCoalescer() *readcache.Group[capturedResponse] {
	group, err := readcache.NewGroup[capturedResponse](readcache.Limits{MaxKeys: maxCoalesceKeys, MaxFollowers: maxCoalesceFollowers, MaxKeyBytes: maxCoalesceKeyBytes})
	if err != nil {
		panic(err)
	} // compile-time positive limits
	return group
}
