package cache

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net/http"
)

// preparePOSTBody snapshots admitted bodies for hashing, proxying and refresh.
// Oversized streams retain their original closer and every byte already read.
func preparePOSTBody(r *http.Request, limit int64) (digest string, admitted bool, err error) {
	if len(r.Trailer) > 0 || r.ContentLength > limit || limit == math.MaxInt64 {
		return "", false, nil
	}
	var body []byte
	if r.Body != nil {
		original := r.Body
		body, err = io.ReadAll(io.LimitReader(original, limit+1))
		if err != nil {
			_ = original.Close()
			return "", false, err
		}
		if int64(len(body)) > limit {
			r.Body = &prefixedRequestBody{
				Reader: io.MultiReader(bytes.NewReader(body), original),
				Closer: original,
			}
			return "", false, nil
		}
		_ = original.Close()
	}

	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.Body, _ = r.GetBody()
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:]), true, nil
}

type prefixedRequestBody struct {
	io.Reader
	io.Closer
}
