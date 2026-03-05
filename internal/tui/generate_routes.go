package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
)

// RouteSecurityAnswers holds per-route security decisions.
type RouteSecurityAnswers struct {
	IsSecured    bool
	InjectFormat string // e.g. "Bearer {token}", "{token}"
	InjectHeader string // e.g. "Authorization"
	TokenRef     string
	KMSKeyID     string
}

// runRouteSecurityWizard asks if a route needs security (token injection)
// and collects the security configuration. This flow is reusable for both
// config generation and TUI route editing.
func runRouteSecurityWizard() (*RouteSecurityAnswers, error) {
	ans := &RouteSecurityAnswers{
		InjectFormat: "Bearer {token}",
		InjectHeader: "Authorization",
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Route Security"),

			huh.NewConfirm().
				Title("Is this route secured?").
				Description("If yes, the gateway will inject credentials into upstream requests").
				Value(&ans.IsSecured),
		),

		// Security details — shown only when secured
		huh.NewGroup(
			huh.NewInput().
				Title("Token reference").
				Description("Name of the token in the token store (e.g. \"api_token\")").
				Value(&ans.TokenRef).
				Placeholder("api_token"),

			huh.NewInput().
				Title("KMS key ID").
				Description("KMS key used to decrypt this token").
				Value(&ans.KMSKeyID).
				Placeholder("your-kms-key-id"),

			huh.NewInput().
				Title("Injection header").
				Description("HTTP header to inject the token into").
				Value(&ans.InjectHeader).
				Placeholder("Authorization"),

			huh.NewSelect[string]().
				Title("Injection format").
				Description("How the token is formatted in the header value").
				Options(
					huh.NewOption("Bearer {token} — standard OAuth2 format", "Bearer {token}"),
					huh.NewOption("{token} — raw token value", "{token}"),
					huh.NewOption("Token {token} — custom prefix", "Token {token}"),
					huh.NewOption("Basic {token} — Basic auth", "Basic {token}"),
				).
				Value(&ans.InjectFormat),
		).WithHideFunc(func() bool { return !ans.IsSecured }),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form.Run(); err != nil {
		return nil, err
	}

	return ans, nil
}

// runMultiRouteWizard collects routes in a loop, asking after each whether to add more.
// It takes the first route already collected and asks about its security, then loops.
func runMultiRouteWizard(firstRoute GenerateRoute, kmsKeyID string) ([]GenerateRoute, []RouteSecurityAnswers, error) {
	routes := []GenerateRoute{firstRoute}

	// Ask security for first route
	sec, err := runRouteSecurityWizard()
	if err != nil {
		return nil, nil, err
	}
	if sec.KMSKeyID == "" && kmsKeyID != "" {
		sec.KMSKeyID = kmsKeyID
	}
	securities := []*RouteSecurityAnswers{sec}

	// Loop: ask to add more routes
	for {
		addMore := false
		formMore := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("Add another route?").
					Description(fmt.Sprintf("You have %d route(s) configured so far", len(routes))).
					Value(&addMore),
			),
		).WithTheme(huh.ThemeCatppuccin())

		if err := formMore.Run(); err != nil {
			return nil, nil, err
		}

		if !addMore {
			break
		}

		route, routeSec, err := runSingleRouteWizard(kmsKeyID)
		if err != nil {
			return nil, nil, err
		}

		routes = append(routes, route)
		securities = append(securities, routeSec)
	}

	// Convert to non-pointer slice
	result := make([]RouteSecurityAnswers, len(securities))
	for i, s := range securities {
		if s != nil {
			result[i] = *s
		}
	}
	return routes, result, nil
}

// runSingleRouteWizard prompts for a single route definition + its security.
func runSingleRouteWizard(defaultKMSKeyID string) (GenerateRoute, *RouteSecurityAnswers, error) {
	route := GenerateRoute{
		Method:  "get",
		RPS:     "10",
		Burst:   "20",
		MaxWait: "5s",
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("  Add Route"),

			huh.NewInput().
				Title("Route path").
				Description("URL path the gateway will handle").
				Value(&route.Path).
				Placeholder("/api/v1/resource").
				Validate(func(s string) error {
					if s != "" && !strings.HasPrefix(s, "/") {
						return fmt.Errorf("path must start with /")
					}
					return nil
				}),

			huh.NewSelect[string]().
				Title("HTTP method").
				Options(
					huh.NewOption("GET", "get"),
					huh.NewOption("POST", "post"),
					huh.NewOption("PUT", "put"),
					huh.NewOption("DELETE", "delete"),
					huh.NewOption("PATCH", "patch"),
				).
				Value(&route.Method),

			huh.NewInput().
				Title("Backend target URL").
				Description("Upstream service URL to proxy requests to").
				Value(&route.TargetURL).
				Placeholder("http://localhost:3000/api/v1/resource").
				Validate(func(s string) error {
					if s != "" && !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
						return fmt.Errorf("target URL must start with http:// or https://")
					}
					return nil
				}),

			huh.NewInput().
				Title("Requests per second (RPS)").
				Value(&route.RPS).
				Placeholder("10").
				Validate(validatePositiveFloat),

			huh.NewInput().
				Title("Burst size").
				Value(&route.Burst).
				Placeholder("20").
				Validate(validatePositiveInt),

			huh.NewInput().
				Title("Max wait duration").
				Value(&route.MaxWait).
				Placeholder("5s"),
		),
	).WithTheme(huh.ThemeCatppuccin())

	if err := form.Run(); err != nil {
		return route, nil, err
	}

	sec, err := runRouteSecurityWizard()
	if err != nil {
		return route, nil, err
	}
	if sec.KMSKeyID == "" && defaultKMSKeyID != "" {
		sec.KMSKeyID = defaultKMSKeyID
	}

	return route, sec, nil
}
