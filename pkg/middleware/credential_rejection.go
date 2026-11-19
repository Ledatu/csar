package middleware

import (
	"context"
	"sync"
	"time"
)

const rejectionRetry = 5 * time.Second
const maxLocalRejections = 10_000

type localRejection struct {
	acknowledged bool
	reporting    bool
	reportedAt   time.Time
	retryAt      time.Time
}

type credentialRejections struct {
	mu       sync.Mutex
	entries  map[string]localRejection
	overflow bool
}

// credentialAllowed prevents another upstream call even when the rejection RPC
// is unavailable. Local quarantine is keyed by value as well as ref, so an old
// in-flight response cannot clear or poison a replacement's rejection record.
func (a *AuthInjector) credentialAllowed(ctx context.Context, reporter CredentialRejectionReporter, ref, version, fingerprint string) bool {
	key := ref + "\x00" + fingerprint
	a.rejections.mu.Lock()
	entry, blocked := a.rejections.entries[key]
	overflow := a.rejections.overflow
	a.rejections.mu.Unlock()
	if blocked && !entry.acknowledged {
		a.reportCredential(ctx, reporter, ref, version, fingerprint)
	}
	return !blocked && !overflow
}

func (a *AuthInjector) rejectCredential(ctx context.Context, reporter CredentialRejectionReporter, ref, version, fingerprint string) {
	key := ref + "\x00" + fingerprint
	a.rejections.mu.Lock()
	if a.rejections.entries == nil {
		a.rejections.entries = make(map[string]localRejection)
	}
	if _, ok := a.rejections.entries[key]; !ok {
		// Acknowledged records can expire after all bounded in-flight requests have
		// drained; durable coordinator quarantine remains authoritative. Unreported
		// rejections never expire into a vendor retry.
		if len(a.rejections.entries) >= maxLocalRejections {
			now := time.Now()
			for k, entry := range a.rejections.entries {
				if entry.acknowledged && now.Sub(entry.reportedAt) > defaultStaleTTL {
					delete(a.rejections.entries, k)
				}
			}
		}
		if len(a.rejections.entries) >= maxLocalRejections {
			a.rejections.overflow = true
			a.rejections.mu.Unlock()
			return
		}
		a.rejections.entries[key] = localRejection{}
	}
	a.rejections.mu.Unlock()
	a.InvalidateToken(ref)
	a.reportCredential(ctx, reporter, ref, version, fingerprint)
}

func (a *AuthInjector) reportCredential(ctx context.Context, reporter CredentialRejectionReporter, ref, version, fingerprint string) {
	key := ref + "\x00" + fingerprint
	now := time.Now()
	a.rejections.mu.Lock()
	entry, ok := a.rejections.entries[key]
	if !ok || entry.acknowledged || entry.reporting || now.Before(entry.retryAt) {
		a.rejections.mu.Unlock()
		return
	}
	entry.reporting = true
	entry.retryAt = now.Add(rejectionRetry)
	a.rejections.entries[key] = entry
	a.rejections.mu.Unlock()
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), rejectionRetry)
	defer cancel()
	err := reporter.ReportCredentialRejection(bounded, ref, version, fingerprint)
	a.rejections.mu.Lock()
	entry = a.rejections.entries[key]
	entry.reporting = false
	if err != nil {
		entry.retryAt = time.Now().Add(rejectionRetry)
	}
	if err == nil {
		entry.acknowledged = true
		entry.reportedAt = time.Now()
	}
	a.rejections.entries[key] = entry
	a.rejections.mu.Unlock()
	if err != nil {
		a.logger.Warn("upstream credential rejection report failed", "token_ref", ref, "error", err)
	}
}
