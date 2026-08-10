package coordinator

import (
	"context"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/ledatu/csar-core/tokenmint"
)

const (
	defaultMintRefreshTick        = 30 * time.Second
	defaultMintRefreshConcurrency = 4
)

// MintRefresher keeps minted tokens ahead of their refresh point and evicts
// entries nobody is using.
//
// It is deliberately not TokenRefresher: that one polls the whole store and
// diffs versions, which the S3 backend does not even run. This one only ever
// looks at refs already in the cache, which under lazy minting is exactly the
// set of accounts receiving traffic.
type MintRefresher struct {
	authSvc *AuthServiceImpl
	store   *MintingTokenStore
	cfg     *tokenmint.Config
	logger  *slog.Logger

	tick        time.Duration
	concurrency int

	// idleTTL is the widest configured across profiles. A minted entry does
	// not record which profile produced it, and erring wide only delays
	// eviction, never shortens a token's life.
	idleTTL time.Duration

	now func() time.Time
}

// NewMintRefresher builds a refresher. A non-positive tick or concurrency
// falls back to the package defaults.
func NewMintRefresher(authSvc *AuthServiceImpl, store *MintingTokenStore, cfg *tokenmint.Config, tick time.Duration, concurrency int, logger *slog.Logger) *MintRefresher {
	if tick <= 0 {
		tick = defaultMintRefreshTick
	}
	if concurrency <= 0 {
		concurrency = defaultMintRefreshConcurrency
	}
	if logger == nil {
		logger = slog.Default()
	}
	var idleTTL time.Duration
	for name := range cfg.Profiles {
		if ttl := cfg.Profiles[name].IdleTTL; ttl > idleTTL {
			idleTTL = ttl
		}
	}

	return &MintRefresher{
		authSvc:     authSvc,
		store:       store,
		cfg:         cfg,
		logger:      logger,
		tick:        tick,
		concurrency: concurrency,
		idleTTL:     idleTTL,
		now:         time.Now,
	}
}

// SetClock replaces the time source. Test-only.
func (r *MintRefresher) SetClock(now func() time.Time) { r.now = now }

// Run refreshes and evicts on a ticker until ctx is cancelled.
func (r *MintRefresher) Run(ctx context.Context) {
	ticker := time.NewTicker(r.tick)
	defer ticker.Stop()

	r.logger.Info("mint refresher started",
		"tick", r.tick,
		"concurrency", r.concurrency,
	)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("mint refresher stopped")
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}

// RunOnce performs a single eviction-and-refresh pass.
func (r *MintRefresher) RunOnce(ctx context.Context) {
	now := r.now()

	var due []string
	for _, ref := range r.authSvc.MintedRefs() {
		entry, ok := r.authSvc.Entry(ref)
		if !ok || !entry.Minted() {
			continue
		}

		if r.evictIfIdle(ref, entry, now) {
			continue
		}
		if entry.NeedsRefresh(r.jittered(ref, entry, now)) {
			due = append(due, ref)
		}
	}

	if dropped := r.store.Sweep(); dropped > 0 {
		r.logger.Debug("swept idle mint state", "dropped", dropped)
	}
	if len(due) == 0 {
		return
	}

	r.refreshAll(ctx, due)
}

// evictIfIdle drops entries that have expired and gone unused. This is what
// stops accounts that stopped receiving traffic from consuming mint quota
// indefinitely — they fall out of the working set and are re-minted lazily if
// a request ever arrives again.
func (r *MintRefresher) evictIfIdle(ref string, entry TokenEntry, now time.Time) bool {
	if r.idleTTL <= 0 {
		return false
	}

	lastServed, ok := r.authSvc.LastServed(ref)
	if !ok {
		lastServed = entry.Mint.RefreshAfter
	}
	if now.Sub(lastServed) < r.idleTTL {
		return false
	}

	r.authSvc.RemoveToken(ref)
	r.logger.Info("evicted idle minted token",
		"token_ref", ref,
		"idle_for", now.Sub(lastServed),
	)
	return true
}

// jittered offsets a ref's refresh point deterministically so that many
// accounts minted in the same burst do not all come due on the same tick.
func (r *MintRefresher) jittered(ref string, entry TokenEntry, now time.Time) time.Time {
	if entry.Mint == nil || entry.Mint.RefreshAfter.IsZero() || entry.Mint.HardExpiry.IsZero() {
		return now
	}

	window := entry.Mint.HardExpiry.Sub(entry.Mint.RefreshAfter)
	if window <= 0 {
		return now
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(ref))
	// Spread across the first tenth of the refresh window.
	spread := int64(window/10) + 1
	offset := time.Duration(int64(h.Sum32()) % spread)
	return now.Add(-offset)
}

func (r *MintRefresher) refreshAll(ctx context.Context, refs []string) {
	sem := make(chan struct{}, r.concurrency)
	var wg sync.WaitGroup

	for _, ref := range refs {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(ref string) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := r.authSvc.Refresh(ctx, ref); err != nil {
				// The existing token stays cached until hard expiry, and the
				// minter's own backoff prevents a retry storm, so a failure
				// here is worth noting but not worth escalating.
				r.logger.Warn("proactive mint refresh failed",
					"token_ref", ref,
					"error", err,
				)
				return
			}
			r.logger.Debug("proactively refreshed minted token", "token_ref", ref)
		}(ref)
	}

	wg.Wait()
}
