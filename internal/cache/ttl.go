package cache

import (
	cryptorand "crypto/rand"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const dateOnlyLayout = "2006-01-02"

func ttlRuleMatches(rule TTLRule, r *http.Request, now time.Time) bool {
	switch rule.When {
	case "query.date_range_contains_today":
		return queryDateRangeContainsToday(rule, r, now)
	default:
		return false
	}
}

func responseTTLRuleMatches(rule ResponseTTLRule, resp *http.Response) bool {
	if resp == nil {
		return false
	}
	switch rule.When {
	case "response.header_equals":
		return rule.Header != "" && resp.Header.Get(rule.Header) == rule.Value
	default:
		return false
	}
}

func applyTTLJitter(ttl time.Duration, spec, _ string) time.Duration {
	if ttl <= 0 || strings.TrimSpace(spec) == "" {
		return ttl
	}
	maxJitter := time.Duration(0)
	spec = strings.TrimSpace(spec)
	if strings.HasSuffix(spec, "%") {
		pctRaw := strings.TrimSuffix(spec, "%")
		pct, err := strconv.ParseFloat(pctRaw, 64)
		if err != nil || pct <= 0 {
			return ttl
		}
		if pct > 100 {
			pct = 100
		}
		maxJitter = time.Duration(float64(ttl) * pct / 100)
	} else {
		d, err := time.ParseDuration(spec)
		if err != nil || d <= 0 {
			return ttl
		}
		maxJitter = d
	}
	if maxJitter <= 0 {
		return ttl
	}
	if maxJitter > ttl {
		maxJitter = ttl
	}
	reduction := randomDuration(maxJitter)
	return ttl - reduction
}

func randomDuration(jitterMax time.Duration) time.Duration {
	if jitterMax <= 0 {
		return 0
	}
	limit := new(big.Int).SetInt64(int64(jitterMax))
	limit.Add(limit, big.NewInt(1))
	n, err := cryptorand.Int(cryptorand.Reader, limit)
	if err == nil {
		return time.Duration(n.Int64())
	}
	return 0
}

func queryDateRangeContainsToday(rule TTLRule, r *http.Request, now time.Time) bool {
	if r == nil {
		return false
	}
	fromName := rule.From
	if fromName == "" {
		fromName = "date_from"
	}
	toName := rule.To
	if toName == "" {
		toName = "date_to"
	}

	from, err := time.Parse(dateOnlyLayout, r.URL.Query().Get(fromName))
	if err != nil {
		return false
	}
	to, err := time.Parse(dateOnlyLayout, r.URL.Query().Get(toName))
	if err != nil {
		return false
	}
	if to.Before(from) {
		return false
	}

	today, err := time.Parse(dateOnlyLayout, now.Format(dateOnlyLayout))
	if err != nil {
		return false
	}
	return !today.Before(from) && !today.After(to)
}
