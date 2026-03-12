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
// The full RouteConfig is stored in the entry so the coordinator can push
// the complete configuration to routers via gRPC.
func ConfigToRouteEntries(cfg *config.Config) map[string]statestore.RouteEntry {
	entries := make(map[string]statestore.RouteEntry)

	flatRoutes := cfg.FlatRoutes()
	for i := range flatRoutes {
		fr := &flatRoutes[i]
		routeID := strings.ToUpper(fr.Method) + ":" + fr.Path

		entries[routeID] = statestore.RouteEntry{
			ID:     routeID,
			Path:   fr.Path,
			Method: strings.ToUpper(fr.Method),
			Route:  fr.Route,
		}
	}

	return entries
}
