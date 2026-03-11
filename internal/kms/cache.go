package kms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// CachingProvider wraps any Provider with an in-memory TTL cache
// and singleflight deduplication to prevent thundering herd on cache miss.
type CachingProvider struct {
	inner      Provider
	ttl        time.Duration
	maxEntries int // 0 = unlimited

	mu    sync.RWMutex
	cache map[string]*cacheEntry

	sf singleflight.Group
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewCachingProvider wraps the given Provider with TTL-based caching.
// maxEntries limits the number of cached entries (0 = unlimited).
func NewCachingProvider(inner Provider, ttl time.Duration, maxEntries int) *CachingProvider {
	return &CachingProvider{
		inner:      inner,
		ttl:        ttl,
		maxEntries: maxEntries,
		cache:      make(map[string]*cacheEntry),
	}
}

// Name returns the inner provider's name with a "(cached)" suffix.
func (c *CachingProvider) Name() string {
	return c.inner.Name() + " (cached)"
}

// Health delegates to the inner provider.
func (c *CachingProvider) Health(ctx context.Context) error {
	return c.inner.Health(ctx)
}

// Encrypt delegates to the inner provider (encryption is not cached).
func (c *CachingProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	return c.inner.Encrypt(ctx, keyID, plaintext)
}

// Decrypt decrypts ciphertext, caching the result by a cache key derived from keyID + ciphertext hash.
// Uses singleflight to prevent multiple concurrent decryptions of the same ciphertext.
func (c *CachingProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	cacheKey := c.cacheKey("decrypt", keyID, ciphertext)

	// Check cache
	if data, ok := c.getCache(cacheKey); ok {
		return data, nil
	}

	// Singleflight: deduplicate concurrent calls for the same key
	result, err, _ := c.sf.Do(cacheKey, func() (interface{}, error) {
		// Double-check cache (another goroutine may have populated it)
		if data, ok := c.getCache(cacheKey); ok {
			return data, nil
		}

		plaintext, err := c.inner.Decrypt(ctx, keyID, ciphertext)
		if err != nil {
			return nil, err
		}

		c.setCache(cacheKey, plaintext)
		return plaintext, nil
	})

	if err != nil {
		return nil, err
	}

	b, ok := result.([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected cache result type")
	}
	return b, nil
}

// Close releases the inner provider and clears the cache.
func (c *CachingProvider) Close() error {
	c.mu.Lock()
	c.cache = make(map[string]*cacheEntry)
	c.mu.Unlock()
	return c.inner.Close()
}

// Invalidate removes a specific cache entry.
func (c *CachingProvider) Invalidate(cacheKey string) {
	c.mu.Lock()
	delete(c.cache, cacheKey)
	c.mu.Unlock()
}

// InvalidateAll clears the entire cache.
func (c *CachingProvider) InvalidateAll() {
	c.mu.Lock()
	c.cache = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

func (c *CachingProvider) getCache(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}

	// Return a copy to prevent mutation
	data := make([]byte, len(entry.data))
	copy(data, entry.data)
	return data, true
}

func (c *CachingProvider) setCache(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stored := make([]byte, len(data))
	copy(stored, data)

	now := time.Now()

	// Enforce max_entries: evict expired entries first, then oldest if still over limit.
	if c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
		// Pass 1: remove expired entries.
		for k, e := range c.cache {
			if now.After(e.expiresAt) {
				delete(c.cache, k)
			}
		}
		// Pass 2: if still at/over limit, remove an arbitrary entry (map iteration order is random).
		for len(c.cache) >= c.maxEntries {
			for k := range c.cache {
				delete(c.cache, k)
				break
			}
		}
	}

	c.cache[key] = &cacheEntry{
		data:      stored,
		expiresAt: now.Add(c.ttl),
	}
}

func (c *CachingProvider) cacheKey(op, keyID string, data []byte) string {
	// Use SHA-256 over (op || 0x00 || keyID || 0x00 || data) for collision resistance.
	h := sha256.New()
	h.Write([]byte(op))
	h.Write([]byte{0})
	h.Write([]byte(keyID))
	h.Write([]byte{0})
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
