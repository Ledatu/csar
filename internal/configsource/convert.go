package configsource

import (
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
)

// ConfigToRouteEntries converts a parsed Config into a map of RouteEntry
// for loading into the coordinator's StateStore.
//
// Each (path, method) pair produces a separate RouteEntry. The route ID
// format is "METHOD:PATH" (e.g., "GET:/api/v1/users").
//
// Only fields supported by RouteEntry are mapped; richer config features
// (CORS, retry, redact, cache, auth-validate, etc.) are handled locally
// by the router and are not part of the distributed route snapshot.
func ConfigToRouteEntries(cfg *config.Config) map[string]statestore.RouteEntry {
	entries := make(map[string]statestore.RouteEntry)

	for _, fr := range cfg.FlatRoutes() {
		routeID := strings.ToUpper(fr.Method) + ":" + fr.Path

		entry := statestore.RouteEntry{
			ID:     routeID,
			Path:   fr.Path,
			Method: strings.ToUpper(fr.Method),
		}

		// Backend → TargetURL.
		// Prefer explicit TargetURL; fall back to first target in load-balanced list.
		if fr.Route.Backend.TargetURL != "" {
			entry.TargetURL = fr.Route.Backend.TargetURL
		} else if len(fr.Route.Backend.Targets) > 0 {
			entry.TargetURL = fr.Route.Backend.Targets[0]
		}

		// Security → SecurityEntry (first credential only;
		// StateStore supports a single security binding per route).
		if len(fr.Route.Security) > 0 {
			sec := fr.Route.Security[0]
			entry.Security = &statestore.SecurityEntry{
				KMSKeyID:     sec.KMSKeyID,
				TokenRef:     sec.TokenRef,
				InjectHeader: sec.InjectHeader,
				InjectFormat: sec.InjectFormat,
			}
		}

		// Traffic → TrafficEntry.
		if fr.Route.Traffic != nil {
			entry.Traffic = &statestore.TrafficEntry{
				RPS:     fr.Route.Traffic.RPS,
				Burst:   fr.Route.Traffic.Burst,
				MaxWait: fr.Route.Traffic.MaxWait.Duration,
			}
		}

		// Resilience → ResilienceProfile name.
		if fr.Route.Resilience != nil {
			entry.ResilienceProfile = fr.Route.Resilience.CircuitBreaker
		}

		entries[routeID] = entry
	}

	return entries
}
