package configsource

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	coresrc "github.com/ledatu/csar-core/configsource"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
)

// NewConfigWatcher creates a ConfigWatcher that applies csar-coordinator's
// route-diff logic inside the ApplyFunc closure. The generic polling,
// ETag, and hash-checking mechanics are handled by csar-core.
func NewConfigWatcher(
	source coresrc.ConfigSource,
	store statestore.StateStore,
	logger *slog.Logger,
	opts ...coresrc.WatcherOption,
) *coresrc.ConfigWatcher {
	var lastRoutes map[string]statestore.RouteEntry
	seeded := false

	applyFn := func(ctx context.Context, data []byte) (bool, error) {
		// On first apply, seed from persistent store so that routes deleted
		// from config before this restart are properly removed.
		if !seeded {
			existing, err := store.GetRoutes(ctx)
			if err != nil {
				logger.Warn("could not seed routes from store; treating as empty", "error", err)
			} else {
				lastRoutes = make(map[string]statestore.RouteEntry, len(existing))
				for _, r := range existing {
					lastRoutes[r.ID] = r
				}
			}
			seeded = true
		}

		cfg, err := config.ParseBytes(data)
		if err != nil {
			return false, fmt.Errorf("parsing config: %w", err)
		}

		newRoutes := ConfigToRouteEntries(cfg)

		added, updated, deleted := diffRoutes(lastRoutes, newRoutes)

		for _, r := range added {
			if err := store.PutRoute(ctx, r); err != nil {
				return false, fmt.Errorf("adding route %s: %w", r.ID, err)
			}
		}
		for _, r := range updated {
			if err := store.PutRoute(ctx, r); err != nil {
				return false, fmt.Errorf("updating route %s: %w", r.ID, err)
			}
		}
		for _, r := range deleted {
			if err := store.DeleteRoute(ctx, r.ID); err != nil {
				return false, fmt.Errorf("deleting route %s: %w", r.ID, err)
			}
		}

		lastRoutes = newRoutes

		totalChanges := len(added) + len(updated) + len(deleted)
		if totalChanges > 0 {
			logger.Info("routes applied",
				"added", len(added),
				"updated", len(updated),
				"deleted", len(deleted),
				"total_routes", len(newRoutes),
			)
		} else {
			logger.Debug("routes unchanged after re-parse",
				"total_routes", len(newRoutes),
			)
		}

		return totalChanges > 0, nil
	}

	return coresrc.NewConfigWatcher(source, applyFn, logger, opts...)
}

// diffRoutes computes the difference between old and new route maps.
func diffRoutes(
	old, newMap map[string]statestore.RouteEntry,
) (added, updated, deleted []statestore.RouteEntry) {
	for id, newEntry := range newMap {
		oldEntry, exists := old[id]
		if !exists {
			added = append(added, newEntry)
		} else if !routeEqual(oldEntry, newEntry) {
			updated = append(updated, newEntry)
		}
	}

	for id, oldEntry := range old {
		if _, exists := newMap[id]; !exists {
			deleted = append(deleted, oldEntry)
		}
	}

	return added, updated, deleted
}

func routeEqual(a, b statestore.RouteEntry) bool {
	if a.ID != b.ID || a.Path != b.Path || a.Method != b.Method ||
		a.TargetURL != b.TargetURL || a.ResilienceProfile != b.ResilienceProfile {
		return false
	}

	if !reflect.DeepEqual(a.Security, b.Security) {
		return false
	}

	if !reflect.DeepEqual(a.Traffic, b.Traffic) {
		return false
	}

	return true
}
