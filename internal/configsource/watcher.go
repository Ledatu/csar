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

// ConfigCallback receives the resolved config at a watcher lifecycle boundary.
type ConfigCallback func(cfg *config.Config)

// WatcherOption configures the config watcher behavior.
type WatcherOption func(*watcherOpts)

type watcherOpts struct {
	onConfigParsed  ConfigCallback
	onConfigApplied ConfigCallback
}

// WithOnConfigParsed registers a callback before route writes. Publication must
// use WithOnConfigApplied so a failed write cannot publish an incomplete config.
func WithOnConfigParsed(fn ConfigCallback) WatcherOption {
	return func(o *watcherOpts) { o.onConfigParsed = fn }
}

// WithOnConfigApplied registers a notification after all route writes succeed.
// It also runs for policy-only updates, which produce no route-store events.
func WithOnConfigApplied(fn ConfigCallback) WatcherOption {
	return func(o *watcherOpts) { o.onConfigApplied = fn }
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

	applyFn := func(ctx context.Context, data []byte) (bool, error) {
		cfg, err := config.ParseBytes(data)
		if err != nil {
			return false, fmt.Errorf("parsing config: %w", err)
		}

		if wo.onConfigParsed != nil {
			wo.onConfigParsed(cfg)
		}

		newRoutes := ConfigToRouteEntries(cfg)
		// A previous apply may have failed after writing only some routes.
		// Reconcile actual state so retries and rollbacks remove those leftovers.
		existing, err := store.GetRoutes(ctx)
		if err != nil {
			return false, fmt.Errorf("reading current routes: %w", err)
		}
		lastRoutes := make(map[string]statestore.RouteEntry, len(existing))
		for i := range existing {
			lastRoutes[existing[i].ID] = existing[i]
		}

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

		if wo.onConfigApplied != nil {
			wo.onConfigApplied(cfg)
		}

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

		// A top-level apply can change policy without producing a route diff.
		return totalChanges > 0 || wo.onConfigApplied != nil, nil
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
