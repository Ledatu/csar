package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrCacheMiss indicates the cache store has no usable entry for the key.
	ErrCacheMiss = errors.New("cache miss")
	// ErrStoreUnhealthy indicates the external store is in a cooldown window.
	ErrStoreUnhealthy = errors.New("cache store unhealthy")
)

const (
	defaultErrorThreshold = 3
	defaultCooldown       = 30 * time.Second
)

// Entry is a cached HTTP response.
type Entry struct {
	StatusCode        int              `json:"status_code"`
	Headers           http.Header      `json:"headers"`
	Body              []byte           `json:"body"`
	ETag              string           `json:"etag,omitempty"`
	ContentType       string           `json:"content_type,omitempty"`
	ExpiresAt         time.Time        `json:"expires_at"`
	StaleExpiresAt    time.Time        `json:"stale_expires_at,omitempty"`
	NamespaceVersions map[string]int64 `json:"namespace_versions,omitempty"`
}

// SetOptions controls cache writes.
type SetOptions struct {
	TTL               time.Duration
	StaleTTL          time.Duration
	Tags              []string
	NamespaceVersions map[string]int64
	MaxEntries        int
}

// Store is a response cache backend.
type Store interface {
	Name() string
	GetFresh(ctx context.Context, key string, namespaceVersions map[string]int64) (*Entry, error)
	GetStale(ctx context.Context, key string, namespaceVersions map[string]int64) (*Entry, error)
	Set(ctx context.Context, key string, entry *Entry, opts SetOptions) error
	DeleteByTag(ctx context.Context, tag string) error
	BumpNamespace(ctx context.Context, namespace string) error
	GetNamespaceVersions(ctx context.Context, namespaces []string) (map[string]int64, error)
}

type memoryEntry struct {
	entry *Entry
	tags  []string
	prev  *memoryEntry
	next  *memoryEntry
	key   string
}

// MemoryStore is an in-process LRU response cache.
type MemoryStore struct {
	mu       sync.RWMutex
	entries  map[string]*memoryEntry
	tagIndex map[string]map[string]struct{}
	versions map[string]int64
	head     *memoryEntry
	tail     *memoryEntry
	size     int
}

// NewMemoryStore creates an in-process cache store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries:  make(map[string]*memoryEntry),
		tagIndex: make(map[string]map[string]struct{}),
		versions: make(map[string]int64),
	}
}

func (s *MemoryStore) Name() string { return "memory" }

func (s *MemoryStore) GetFresh(_ context.Context, key string, namespaceVersions map[string]int64) (*Entry, error) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, ErrCacheMiss
	}
	if !versionsMatch(e.entry.NamespaceVersions, namespaceVersions) {
		return nil, ErrCacheMiss
	}
	if now.After(e.entry.ExpiresAt) {
		if e.entry.StaleExpiresAt.IsZero() || now.After(e.entry.StaleExpiresAt) {
			s.deleteLocked(e)
		}
		return nil, ErrCacheMiss
	}

	s.removeFromList(e)
	s.addToFront(e)
	return cloneEntry(e.entry), nil
}

func (s *MemoryStore) GetStale(_ context.Context, key string, namespaceVersions map[string]int64) (*Entry, error) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		return nil, ErrCacheMiss
	}
	if !versionsMatch(e.entry.NamespaceVersions, namespaceVersions) {
		return nil, ErrCacheMiss
	}
	if !now.After(e.entry.ExpiresAt) {
		return nil, ErrCacheMiss
	}
	if e.entry.StaleExpiresAt.IsZero() || now.After(e.entry.StaleExpiresAt) {
		s.deleteLocked(e)
		return nil, ErrCacheMiss
	}

	s.removeFromList(e)
	s.addToFront(e)
	return cloneEntry(e.entry), nil
}

func (s *MemoryStore) Set(_ context.Context, key string, entry *Entry, opts SetOptions) error {
	if opts.TTL <= 0 {
		return fmt.Errorf("memory cache set: ttl must be positive")
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}

	now := time.Now()
	entry = cloneEntry(entry)
	entry.ExpiresAt = now.Add(opts.TTL)
	if opts.StaleTTL > 0 {
		entry.StaleExpiresAt = entry.ExpiresAt.Add(opts.StaleTTL)
	} else {
		entry.StaleExpiresAt = entry.ExpiresAt
	}
	entry.NamespaceVersions = cloneNamespaceVersions(opts.NamespaceVersions)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.entries[key]; ok {
		s.deleteLocked(existing)
	}

	e := &memoryEntry{
		entry: entry,
		tags:  append([]string(nil), opts.Tags...),
		key:   key,
	}
	s.entries[key] = e
	s.addToFront(e)
	s.size++
	for _, tag := range e.tags {
		if s.tagIndex[tag] == nil {
			s.tagIndex[tag] = make(map[string]struct{})
		}
		s.tagIndex[tag][key] = struct{}{}
	}

	for s.size > opts.MaxEntries && s.tail != nil {
		s.deleteLocked(s.tail)
	}
	return nil
}

func (s *MemoryStore) BumpNamespace(_ context.Context, namespace string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[namespace]++
	return nil
}

func (s *MemoryStore) GetNamespaceVersions(_ context.Context, namespaces []string) (map[string]int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := make(map[string]int64, len(namespaces))
	for _, namespace := range namespaces {
		versions[namespace] = s.versions[namespace]
	}
	return versions, nil
}

func (s *MemoryStore) DeleteByTag(_ context.Context, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys := s.tagIndex[tag]
	if len(keys) == 0 {
		return ErrCacheMiss
	}
	for key := range keys {
		if e, ok := s.entries[key]; ok {
			s.deleteLocked(e)
		}
	}
	delete(s.tagIndex, tag)
	return nil
}

func (s *MemoryStore) deleteLocked(e *memoryEntry) {
	s.removeFromList(e)
	delete(s.entries, e.key)
	for _, tag := range e.tags {
		delete(s.tagIndex[tag], e.key)
		if len(s.tagIndex[tag]) == 0 {
			delete(s.tagIndex, tag)
		}
	}
	s.size--
}

func (s *MemoryStore) addToFront(e *memoryEntry) {
	e.prev = nil
	e.next = s.head
	if s.head != nil {
		s.head.prev = e
	}
	s.head = e
	if s.tail == nil {
		s.tail = e
	}
}

func (s *MemoryStore) removeFromList(e *memoryEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if s.head == e {
		s.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if s.tail == e {
		s.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// RedisStore is a distributed response cache store.
type RedisStore struct {
	client *redis.Client
	prefix string
	health *storeHealth
}

// NewRedisStore creates a Redis response cache store.
func NewRedisStore(client *redis.Client, keyPrefix string) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "csar:"
	}
	return &RedisStore{
		client: client,
		prefix: keyPrefix + "cache:",
		health: &storeHealth{
			errorThreshold: defaultErrorThreshold,
			cooldown:       defaultCooldown,
		},
	}
}

func (s *RedisStore) Name() string { return "redis" }

func (s *RedisStore) GetFresh(ctx context.Context, key string, namespaceVersions map[string]int64) (*Entry, error) {
	return s.get(ctx, key, namespaceVersions, false)
}

func (s *RedisStore) GetStale(ctx context.Context, key string, namespaceVersions map[string]int64) (*Entry, error) {
	return s.get(ctx, key, namespaceVersions, true)
}

func (s *RedisStore) get(ctx context.Context, key string, namespaceVersions map[string]int64, allowStale bool) (*Entry, error) {
	if err := s.health.check(); err != nil {
		return nil, err
	}

	raw, err := s.client.Get(ctx, s.responseKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrCacheMiss
		}
		s.health.recordError(false)
		return nil, err
	}

	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		s.health.recordError(false)
		return nil, err
	}
	if !versionsMatch(entry.NamespaceVersions, namespaceVersions) {
		return nil, ErrCacheMiss
	}
	now := time.Now()
	if allowStale {
		if !now.After(entry.ExpiresAt) {
			return nil, ErrCacheMiss
		}
		if entry.StaleExpiresAt.IsZero() || now.After(entry.StaleExpiresAt) {
			return nil, ErrCacheMiss
		}
	} else if now.After(entry.ExpiresAt) {
		return nil, ErrCacheMiss
	}
	s.health.recordSuccess()
	return &entry, nil
}

func (s *RedisStore) Set(ctx context.Context, key string, entry *Entry, opts SetOptions) error {
	if err := s.health.check(); err != nil {
		return err
	}
	if opts.TTL <= 0 {
		return fmt.Errorf("redis cache set: ttl must be positive")
	}

	now := time.Now()
	entry = cloneEntry(entry)
	entry.ExpiresAt = now.Add(opts.TTL)
	if opts.StaleTTL > 0 {
		entry.StaleExpiresAt = entry.ExpiresAt.Add(opts.StaleTTL)
	} else {
		entry.StaleExpiresAt = entry.ExpiresAt
	}
	entry.NamespaceVersions = cloneNamespaceVersions(opts.NamespaceVersions)

	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	expireAfter := time.Until(entry.StaleExpiresAt)
	if expireAfter <= 0 {
		expireAfter = opts.TTL
	}
	rkey := s.responseKey(key)
	pipe := s.client.Pipeline()
	pipe.Set(ctx, rkey, payload, expireAfter)
	for _, tag := range opts.Tags {
		tkey := s.tagKey(tag)
		// Do not expire tag indexes with individual response TTLs. A short-lived
		// response must not remove the tag index for longer-lived responses.
		pipe.SAdd(ctx, tkey, rkey)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		s.health.recordError(false)
		return err
	}

	s.health.recordSuccess()
	return nil
}

func (s *RedisStore) BumpNamespace(ctx context.Context, namespace string) error {
	if err := s.health.check(); err != nil {
		return err
	}
	if err := s.client.Incr(ctx, s.namespaceKey(namespace)).Err(); err != nil {
		s.health.recordError(true)
		return err
	}
	s.health.recordSuccess()
	return nil
}

func (s *RedisStore) GetNamespaceVersions(ctx context.Context, namespaces []string) (map[string]int64, error) {
	if err := s.health.check(); err != nil {
		return nil, err
	}
	versions := make(map[string]int64, len(namespaces))
	if len(namespaces) == 0 {
		return versions, nil
	}
	pipe := s.client.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(namespaces))
	for _, namespace := range namespaces {
		cmds[namespace] = pipe.Get(ctx, s.namespaceKey(namespace))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		s.health.recordError(false)
		return nil, err
	}
	for namespace, cmd := range cmds {
		v, err := cmd.Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			s.health.recordError(false)
			return nil, err
		}
		versions[namespace] = v
	}
	s.health.recordSuccess()
	return versions, nil
}

func (s *RedisStore) DeleteByTag(ctx context.Context, tag string) error {
	if err := s.health.check(); err != nil {
		return err
	}

	tkey := s.tagKey(tag)
	keys, err := s.client.SMembers(ctx, tkey).Result()
	if err != nil {
		s.health.recordError(true)
		return err
	}
	if len(keys) == 0 {
		return ErrCacheMiss
	}

	pipe := s.client.Pipeline()
	for _, key := range keys {
		pipe.Del(ctx, key)
	}
	pipe.Del(ctx, tkey)
	if _, err := pipe.Exec(ctx); err != nil {
		s.health.recordError(true)
		return err
	}

	s.health.recordSuccess()
	return nil
}

func (s *RedisStore) responseKey(key string) string {
	return s.prefix + "response:" + key
}

func (s *RedisStore) tagKey(tag string) string {
	return s.prefix + "tag:" + hashString(tag)
}

func (s *RedisStore) namespaceKey(namespace string) string {
	return s.prefix + "namespace:" + hashString(namespace)
}

type storeHealth struct {
	mu             sync.Mutex
	consecutive    int
	unhealthyUntil time.Time
	errorThreshold int
	cooldown       time.Duration
}

func (h *storeHealth) check() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.unhealthyUntil.IsZero() && time.Now().Before(h.unhealthyUntil) {
		return ErrStoreUnhealthy
	}
	if !h.unhealthyUntil.IsZero() {
		h.unhealthyUntil = time.Time{}
		h.consecutive = 0
	}
	return nil
}

func (h *storeHealth) recordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecutive = 0
	h.unhealthyUntil = time.Time{}
}

func (h *storeHealth) recordError(forceCooldown bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecutive++
	if forceCooldown || h.consecutive >= h.errorThreshold {
		h.unhealthyUntil = time.Now().Add(h.cooldown)
	}
}

func cloneEntry(e *Entry) *Entry {
	if e == nil {
		return nil
	}
	return &Entry{
		StatusCode:        e.StatusCode,
		Headers:           cloneHeader(e.Headers),
		Body:              append([]byte(nil), e.Body...),
		ETag:              e.ETag,
		ContentType:       e.ContentType,
		ExpiresAt:         e.ExpiresAt,
		StaleExpiresAt:    e.StaleExpiresAt,
		NamespaceVersions: cloneNamespaceVersions(e.NamespaceVersions),
	}
}

func cloneNamespaceVersions(in map[string]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func versionsMatch(entryVersions, current map[string]int64) bool {
	for namespace, currentVersion := range current {
		if entryVersions[namespace] != currentVersion {
			return false
		}
	}
	return true
}
