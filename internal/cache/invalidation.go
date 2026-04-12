package cache

import (
	"sync"
	"time"
)

type debounceEntry struct {
	timer *time.Timer
	dirty bool
}

type invalidationDebouncer struct {
	rc      *ResponseCache
	mu      sync.Mutex
	entries map[string]*debounceEntry
}

func newInvalidationDebouncer(rc *ResponseCache) *invalidationDebouncer {
	return &invalidationDebouncer{
		rc:      rc,
		entries: make(map[string]*debounceEntry),
	}
}

func (d *invalidationDebouncer) invalidateTag(store Store, cfg InvalidationConfig, tag string) {
	key := store.Name() + ":tag:" + tag
	d.run(key, cfg.RouteKey, cfg.Debounce, func() { d.rc.invalidateTag(store, cfg, tag) })
}

func (d *invalidationDebouncer) bumpNamespace(store Store, cfg InvalidationConfig, namespace string) {
	key := store.Name() + ":namespace:" + namespace
	d.run(key, cfg.RouteKey, cfg.Debounce, func() { d.rc.bumpNamespace(store, cfg, namespace) })
}

func (d *invalidationDebouncer) run(key, route string, delay time.Duration, fn func()) {
	d.mu.Lock()
	if entry, ok := d.entries[key]; ok {
		entry.dirty = true
		d.rc.record(route, "invalidation_debounced")
		d.mu.Unlock()
		return
	}

	entry := &debounceEntry{}
	d.entries[key] = entry
	d.mu.Unlock()

	fn()

	entry.timer = time.AfterFunc(delay, func() {
		d.mu.Lock()
		dirty := entry.dirty
		delete(d.entries, key)
		d.mu.Unlock()
		if dirty {
			fn()
		}
	})
}
