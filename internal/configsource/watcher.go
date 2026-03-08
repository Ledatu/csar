package configsource

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
)

// ConfigWatcher periodically polls a ConfigSource, validates the config,
// checks SHA-256 integrity, computes diffs against the current state,
// and applies changes to the StateStore.
//
// It follows the same poll + diff + apply pattern as TokenRefresher.
type ConfigWatcher struct {
	source ConfigSource
	store  statestore.StateStore
	logger *slog.Logger

	mu         sync.Mutex
	lastETag   string
	lastHash   string
	lastRoutes map[string]statestore.RouteEntry

	hashPolicy HashPolicy
	pinnedHash string
}

// WatcherOption configures a ConfigWatcher.
type WatcherOption func(*ConfigWatcher)

// WithHashPolicy sets the hash validation strategy.
func WithHashPolicy(p HashPolicy) WatcherOption {
	return func(w *ConfigWatcher) { w.hashPolicy = p }
}

// WithPinnedHash sets the expected SHA-256 hash for HashPinned policy.
func WithPinnedHash(hash string) WatcherOption {
	return func(w *ConfigWatcher) { w.pinnedHash = hash }
}

// NewConfigWatcher creates a new watcher with the given source and state store.
// By default, TOFU hash policy is used.
func NewConfigWatcher(
	source ConfigSource,
	store statestore.StateStore,
	logger *slog.Logger,
	opts ...WatcherOption,
) *ConfigWatcher {
	w := &ConfigWatcher{
		source:     source,
		store:      store,
		logger:     logger,
		hashPolicy: HashTOFU,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Apply performs one cycle: fetch → validate → hash check → diff → apply.
// Returns true if the config was updated, false if unchanged or skipped.
//
// Apply holds w.mu for its entire execution so that concurrent callers
// (e.g. if RunPeriodicWatch were started twice) cannot interleave their
// diff + store operations, which would produce conflicting PutRoute /
// DeleteRoute calls and leave the store in an undefined state.
func (w *ConfigWatcher) Apply(ctx context.Context) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 1. Fetch from source (outside the critical section would be ideal for
	// throughput, but correctness requires the full cycle to be serialised).
	fetched, err := w.source.Fetch(ctx)
	if err != nil {
		return false, fmt.Errorf("fetching config: %w", err)
	}

	// 2. Skip if unchanged (nil Data = HTTP 304, or same ETag).
	if fetched.Data == nil {
		// HTTP 304 Not Modified — source confirmed no changes.
		return false, nil
	}
	if fetched.ETag != "" && fetched.ETag == w.lastETag {
		return false, nil
	}

	// 3. Compute SHA-256 hash.
	currentHash := ComputeSHA256(fetched.Data)

	// 4. Hash validation.
	if err := ValidateHash(w.hashPolicy, w.pinnedHash, currentHash, w.lastHash, fetched.ETag, w.lastETag); err != nil {
		return false, fmt.Errorf("hash validation: %w", err)
	}

	// 5. Parse and validate config.
	cfg, err := config.ParseBytes(fetched.Data)
	if err != nil {
		return false, fmt.Errorf("parsing config: %w", err)
	}

	// 6. Convert to route entries.
	newRoutes := ConfigToRouteEntries(cfg)

	// 7. Diff against current state and apply.
	added, updated, deleted := diffRoutes(w.lastRoutes, newRoutes)

	// Apply additions and updates.
	// On any failure we clear lastETag so the ETag short-circuit cannot hide
	// the partially-applied state on the next poll; the watcher will re-fetch
	// and retry the full diff rather than skipping the unchanged ETag.
	for _, r := range added {
		if err := w.store.PutRoute(ctx, r); err != nil {
			w.lastETag = ""
			return false, fmt.Errorf("adding route %s: %w", r.ID, err)
		}
	}
	for _, r := range updated {
		if err := w.store.PutRoute(ctx, r); err != nil {
			w.lastETag = ""
			return false, fmt.Errorf("updating route %s: %w", r.ID, err)
		}
	}
	for _, r := range deleted {
		if err := w.store.DeleteRoute(ctx, r.ID); err != nil {
			w.lastETag = ""
			return false, fmt.Errorf("deleting route %s: %w", r.ID, err)
		}
	}

	// 8. Update tracked state.
	w.lastETag = fetched.ETag
	w.lastHash = currentHash
	w.lastRoutes = newRoutes

	totalChanges := len(added) + len(updated) + len(deleted)
	if totalChanges > 0 {
		w.logger.Info("config applied",
			"added", len(added),
			"updated", len(updated),
			"deleted", len(deleted),
			"total_routes", len(newRoutes),
			"sha256", currentHash,
		)
	} else {
		w.logger.Debug("config unchanged after re-parse",
			"total_routes", len(newRoutes),
		)
	}

	return totalChanges > 0, nil
}

// RunPeriodicWatch starts a background loop that polls the config source
// at the given interval, validates changes, and applies them to the StateStore.
//
// It blocks until ctx is cancelled.
func (w *ConfigWatcher) RunPeriodicWatch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("config watch loop stopped")
			return
		case <-ticker.C:
			changed, err := w.Apply(ctx)
			if err != nil {
				w.logger.Error("config refresh failed", "error", err)
				continue
			}
			if changed {
				w.logger.Info("config updated from source")
			}
		}
	}
}

// diffRoutes computes the difference between old and new route maps.
// Returns slices of added, updated, and deleted route entries.
func diffRoutes(
	old, new map[string]statestore.RouteEntry,
) (added, updated, deleted []statestore.RouteEntry) {
	// Detect additions and updates.
	for id, newEntry := range new {
		oldEntry, exists := old[id]
		if !exists {
			added = append(added, newEntry)
		} else if !routeEqual(oldEntry, newEntry) {
			updated = append(updated, newEntry)
		}
	}

	// Detect deletions.
	for id, oldEntry := range old {
		if _, exists := new[id]; !exists {
			deleted = append(deleted, oldEntry)
		}
	}

	return added, updated, deleted
}

// routeEqual compares two RouteEntry values for equality.
func routeEqual(a, b statestore.RouteEntry) bool {
	if a.ID != b.ID || a.Path != b.Path || a.Method != b.Method ||
		a.TargetURL != b.TargetURL || a.ResilienceProfile != b.ResilienceProfile {
		return false
	}

	// Compare optional Security.
	if !reflect.DeepEqual(a.Security, b.Security) {
		return false
	}

	// Compare optional Traffic.
	if !reflect.DeepEqual(a.Traffic, b.Traffic) {
		return false
	}

	return true
}
