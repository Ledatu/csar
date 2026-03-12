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

// ConfigCallback is called after config is parsed but before routes are applied.
// It receives the full parsed config for use cases like updating top-level
// policies on the coordinator.
type ConfigCallback func(cfg *config.Config)

// WatcherOption configures the config watcher behavior.
type WatcherOption func(*watcherOpts)

type watcherOpts struct {
	onConfigParsed ConfigCallback
}

// WithOnConfigParsed registers a callback invoked with the full parsed config
// on every successful config apply. Used by the coordinator to capture
// top-level policy maps for gRPC distribution.
func WithOnConfigParsed(fn ConfigCallback) WatcherOption {
	return func(o *watcherOpts) { o.onConfigParsed = fn }
}

// NewConfigWatcher creates a ConfigWatcher that applies csar-coordinator's
// route-diff logic inside the ApplyFunc closure. The generic polling,
// ETag, and hash-checking mechanics are handled by csar-core.
func NewConfigWatcher(
	source coresrc.ConfigSource,
	store statestore.StateStore,
	logger *slog.Logger,
	opts ...coresrc.WatcherOption,
) *coresrc.ConfigWatcher {
	return NewConfigWatcherWithOptions(source, store, logger, nil, opts...)
}

// NewConfigWatcherWithOptions is like NewConfigWatcher but accepts additional
// WatcherOption for callbacks like OnConfigParsed.
func NewConfigWatcherWithOptions(
	source coresrc.ConfigSource,
	store statestore.StateStore,
	logger *slog.Logger,
	wopts []WatcherOption,
	coreOpts ...coresrc.WatcherOption,
) *coresrc.ConfigWatcher {
	var wo watcherOpts
	for _, o := range wopts {
		o(&wo)
	}

	var lastRoutes map[string]statestore.RouteEntry
	seeded := false

	applyFn := func(ctx context.Context, data []byte) (bool, error) {
		if !seeded {
			existing, err := store.GetRoutes(ctx)
			if err != nil {
				logger.Warn("could not seed routes from store; treating as empty", "error", err)
			} else {
				lastRoutes = make(map[string]statestore.RouteEntry, len(existing))
				for i := range existing {
					lastRoutes[existing[i].ID] = existing[i]
				}
			}
			seeded = true
		}

		cfg, err := config.ParseBytes(data)
		if err != nil {
			return false, fmt.Errorf("parsing config: %w", err)
		}

		if wo.onConfigParsed != nil {
			wo.onConfigParsed(cfg)
		}

		newRoutes := ConfigToRouteEntries(cfg)

		added, updated, deleted := diffRoutes(lastRoutes, newRoutes)

		for i := range added {
			if err := store.PutRoute(ctx, added[i]); err != nil {
				return false, fmt.Errorf("adding route %s: %w", added[i].ID, err)
			}
		}
		for i := range updated {
			if err := store.PutRoute(ctx, updated[i]); err != nil {
				return false, fmt.Errorf("updating route %s: %w", updated[i].ID, err)
			}
		}
		for i := range deleted {
			if err := store.DeleteRoute(ctx, deleted[i].ID); err != nil {
				return false, fmt.Errorf("deleting route %s: %w", deleted[i].ID, err)
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

	return coresrc.NewConfigWatcher(source, applyFn, logger, coreOpts...)
}

// diffRoutes computes the difference between old and new route maps.
func diffRoutes(
	old, newMap map[string]statestore.RouteEntry,
) (added, updated, deleted []statestore.RouteEntry) {
	for id := range newMap {
		newEntry := newMap[id]
		oldEntry, exists := old[id]
		if !exists {
			added = append(added, newEntry)
		} else if !routeEqual(oldEntry, newEntry) {
			updated = append(updated, newEntry)
		}
	}

	for id := range old {
		if _, exists := newMap[id]; !exists {
			deleted = append(deleted, old[id])
		}
	}

	return added, updated, deleted
}

func routeEqual(a, b statestore.RouteEntry) bool {
	if a.ID != b.ID || a.Path != b.Path || a.Method != b.Method {
		return false
	}
	return reflect.DeepEqual(a.Route, b.Route)
}
