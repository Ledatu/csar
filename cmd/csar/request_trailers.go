package main

import "net/http"

func preservePOSTTrailers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http fills trailers at EOF on the original request. Initialize the
		// map before tracing/routing copies the request with a new context.
		if r.Method == http.MethodPost && r.Trailer == nil {
			r.Trailer = make(http.Header)
		}
		next.ServeHTTP(w, r)
	})
}
