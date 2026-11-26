package router

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/config"
)

func (r *Router) setupAuthentication(rt *route, fr config.FlatRoute, cfg *config.Config, key string, logger *slog.Logger) error {
	next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serveAfterJWT(w, req, rt) })
	if fr.Route.AuthValidate.Mode != "select" {
		if err := r.setupTerminalAuthentication(rt, fr, cfg, key, logger); err != nil {
			return err
		}
		rt.authentication = rt.wrapAuthentication(next)
		return nil
	}
	if err := fr.Route.AuthValidate.ValidateSelection(); err != nil {
		return fmt.Errorf("route %s: %w", key, err)
	}
	methods := make([]authn.Method, 0, len(fr.Route.AuthValidate.Methods))
	for i := range fr.Route.AuthValidate.Methods {
		child := fr
		child.Route.AuthValidate = &fr.Route.AuthValidate.Methods[i]
		branch := &route{}
		if err := r.setupTerminalAuthentication(branch, child, cfg, key, logger); err != nil {
			return err
		}
		source, err := child.Route.AuthValidate.CredentialSource()
		if err != nil {
			return err
		}
		forwardsEmail := branch.forwardsActorEmail()
		wrap := branch.wrapAuthentication
		methods = append(methods, authn.Method{Source: source, Wrap: func(next http.Handler) http.Handler {
			return wrap(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if forwardsEmail {
					auditEmail(req)
				}
				next.ServeHTTP(w, req)
			}))
		}})
	}
	// Select compiles the wrappers once; requests retain only the chosen handlers,
	// not temporary route objects or per-request selector maps.
	rt.authentication = authn.Select(methods, next)
	return nil
}

func (r *Router) setupTerminalAuthentication(rt *route, fr config.FlatRoute, cfg *config.Config, key string, logger *slog.Logger) error {
	switch fr.Route.AuthValidate.Mode {
	case "session":
		return r.setupSession(rt, fr, cfg, key, logger)
	case "token", "mcp", "mcp-account", "delegated", "delegated-discovery", authntokens.GrantExchange, authntokens.GrantDiscovery, authntokens.GrantResource, authntokens.GrantExchangeV2, authntokens.GrantDiscoveryV2, authntokens.GrantResourceV2, authntokens.AccessResourceV2:
		return r.setupToken(rt, fr, cfg, key, logger)
	case "", "jwt":
		return r.setupJWT(rt, fr, cfg, key, logger)
	default:
		return fmt.Errorf("route %s: unknown auth_validate mode %q", key, fr.Route.AuthValidate.Mode)
	}
}

func (rt *route) wrapAuthentication(next http.Handler) http.Handler {
	switch {
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
