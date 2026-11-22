package authzmw

import "context"

// AuthorizedScope describes the actual successful authorization branch, not a
// client header or the operation's requested attribution resource.
type AuthorizedScope struct{ Subject, Type, ID string }
type authorizedScopeKey struct{}

func ScopeFromContext(ctx context.Context) (AuthorizedScope, bool) {
	scope, ok := ctx.Value(authorizedScopeKey{}).(AuthorizedScope)
	return scope, ok
}
