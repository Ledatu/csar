package authn

import (
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/apierror"
)

// Method binds a credential location to an existing authentication validator.
type Method struct {
	Source string
	Wrap   func(http.Handler) http.Handler
}

// Select validates exactly one presented credential. It never falls back after
// validation failure; duplicate or conflicting credentials are rejected.
func Select(methods []Method, next http.Handler) http.Handler {
	handlers := make([]http.Handler, len(methods))
	clean := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("Authorization")
		r.Header.Del("X-Csar-Authorization")
		r.Header.Del("Cookie")
		next.ServeHTTP(w, r)
	})
	for i, m := range methods {
		handlers[i] = m.Wrap(clean)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := map[string]bool{}
		for _, m := range methods {
			allowed[m.Source] = true
		}
		for _, header := range []string{"Authorization", "X-Csar-Authorization"} {
			if len(r.Header.Values(header)) > 0 && !allowed["header:"+header] {
				apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "unsupported authentication credential").Write(w)
				return
			}
		}
		selected, count := -1, 0
		for i, m := range methods {
			var n int
			if cookie, ok := strings.CutPrefix(m.Source, "cookie:"); ok {
				for _, c := range r.Cookies() {
					if c.Name == cookie {
						n++
					}
				}
			} else if header, ok := strings.CutPrefix(m.Source, "header:"); ok {
				n = len(r.Header.Values(header))
			}
			if n > 0 {
				selected = i
				count += n
			}
		}
		if count != 1 {
			apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "exactly one authentication credential required").Write(w)
			return
		}
		handlers[selected].ServeHTTP(w, r)
	})
}
