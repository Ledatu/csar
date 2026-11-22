package authn

import (
	"context"
	"net/http"
	"time"

	"github.com/ledatu/csar-core/caller"
)

// Source is a private-context authentication result, never a client header.
// ValidUntil also bounds the freshness lease of a cached issuer validation.
type Source struct {
	Caller     *caller.Identity
	ValidUntil time.Time
}
type sourceKey struct{}

func withSource(r *http.Request, id *caller.Identity, until time.Time) *http.Request {
	var source *Source
	if id != nil && !until.IsZero() {
		principal := *id
		source = &Source{Caller: &principal, ValidUntil: until}
	}
	return r.WithContext(context.WithValue(r.Context(), sourceKey{}, source))
}

func SourceFromContext(ctx context.Context) (*Source, bool) {
	source, ok := ctx.Value(sourceKey{}).(*Source)
	if !ok || source == nil || source.Caller == nil {
		return nil, false
	}
	copySource := *source
	principal := *source.Caller
	copySource.Caller = &principal
	return &copySource, true
}
