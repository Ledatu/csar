package router

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/config"
)

func (r *Router) setupAuthentication(rt *route, fr config.FlatRoute, cfg *config.Config, key string, logger *slog.Logger) error {
	switch fr.Route.AuthValidate.Mode {
	case "select":
		if len(fr.Route.AuthValidate.Methods) < 2 || len(fr.Route.AuthValidate.Methods) > 3 {
			return fmt.Errorf("route %s: authentication selection requires 2..3 methods", key)
		}
		for i := range fr.Route.AuthValidate.Methods {
			method := fr.Route.AuthValidate.Methods[i]
			if method.Mode == "select" || len(method.Methods) > 0 {
				return fmt.Errorf("route %s: nested authentication selection", key)
			}
			child := fr
			child.Route.AuthValidate = &method
			branch := &route{}
			if err := r.setupAuthentication(branch, child, cfg, key, logger); err != nil {
				return err
			}
			source, err := method.CredentialSource()
			if err != nil {
				return err
			}
			rt.authMethods = append(rt.authMethods, authn.Method{Source: source, Wrap: branch.wrapAuthentication})
		}
		return nil
	case "session":
		return r.setupSession(rt, fr, cfg, key, logger)
	case "token":
		return r.setupToken(rt, fr, cfg, key, logger)
	case "", "jwt":
		return r.setupJWT(rt, fr, cfg, key, logger)
	default:
		return fmt.Errorf("route %s: unknown auth_validate mode %q", key, fr.Route.AuthValidate.Mode)
	}
}

func (rt *route) wrapAuthentication(next http.Handler) http.Handler {
	switch {
	case len(rt.authMethods) > 0:
		return authn.Select(rt.authMethods, next)
	case rt.sessionConfig != nil && rt.sessionValidator != nil:
		return rt.sessionValidator.Wrap(*rt.sessionConfig, next)
	case rt.tokenConfig != nil && rt.tokenValidator != nil:
		return rt.tokenValidator.Wrap(*rt.tokenConfig, next)
	case rt.jwtConfig != nil && rt.jwtValidator != nil:
		return rt.jwtValidator.Wrap(*rt.jwtConfig, next)
	default:
		return next
	}
}
