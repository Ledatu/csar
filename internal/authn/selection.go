package authn

import (
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/gatewayctx"
)

// Method binds a credential location to an existing authentication validator.
type Method struct {
	Source string
	Wrap   func(http.Handler) http.Handler
}

type selectedMethod struct {
	header  string
	cookie  string
	handler http.Handler
}

// Select compiles the validators once and authenticates exactly one presented
// credential. Validation failure never falls back to another method.
func Select(methods []Method, next http.Handler) http.Handler {
	clean := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("Authorization")
		r.Header.Del(gatewayctx.HeaderCsarAuthorization)
		r.Header.Del("Cookie")
		next.ServeHTTP(w, r)
	})
	compiled := make([]selectedMethod, len(methods))
	authHeaders := [...]string{"Authorization", gatewayctx.HeaderCsarAuthorization}
	var allowed [len(authHeaders)]bool
	for i, m := range methods {
		method := &compiled[i]
		if cookie, ok := strings.CutPrefix(m.Source, "cookie:"); ok {
			method.cookie = cookie
		} else if header, ok := strings.CutPrefix(m.Source, "header:"); ok {
			method.header = http.CanonicalHeaderKey(header)
			for j, name := range authHeaders {
				if method.header == name {
					allowed[j] = true
				}
			}
		}
		method.handler = m.Wrap(clean)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i, header := range authHeaders {
			if len(r.Header.Values(header)) > 0 && !allowed[i] {
				apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "unsupported authentication credential").Write(w)
				return
			}
		}
		selected, count := -1, 0
		cookies := r.Cookies()
		for i, method := range compiled {
			var n int
			if method.cookie != "" {
				for _, c := range cookies {
					if c.Name == method.cookie {
						n++
					}
				}
			} else if method.header != "" {
				n = len(r.Header.Values(method.header))
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
		compiled[selected].handler.ServeHTTP(w, r)
	})
}
