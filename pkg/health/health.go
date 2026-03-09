package health

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Status represents the health status of a CSAR instance.
type Status struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Handler returns an HTTP handler for health checks (liveness probe).
func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{
			Status:  "ok",
			Version: version,
		})
	}
}

// CheckStatus represents the health of a single dependency.
type CheckStatus struct {
	Status string `json:"status"` // "ok", "degraded", "fail"
	Detail string `json:"detail,omitempty"`
}

// ReadinessStatus represents the aggregate readiness with per-dependency checks.
type ReadinessStatus struct {
	Status  string                 `json:"status"` // "ready", "degraded", "not_ready"
	Version string                 `json:"version"`
	Checks  map[string]CheckStatus `json:"checks,omitempty"`
}

// CheckFunc is a function that probes a dependency and returns its status.
type CheckFunc func() CheckStatus

// ReadinessChecker aggregates multiple dependency checks.
type ReadinessChecker struct {
	mu      sync.RWMutex
	checks  map[string]CheckFunc
	version string
	details bool
}

// NewReadinessChecker creates a new readiness checker.
func NewReadinessChecker(version string, includeDetails bool) *ReadinessChecker {
	return &ReadinessChecker{
		checks:  make(map[string]CheckFunc),
		version: version,
		details: includeDetails,
	}
}

// Register adds a named dependency check.
func (rc *ReadinessChecker) Register(name string, check CheckFunc) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.checks[name] = check
}

// Check runs all registered checks and returns aggregate status.
func (rc *ReadinessChecker) Check() ReadinessStatus {
	rc.mu.RLock()
	checks := make(map[string]CheckFunc, len(rc.checks))
	for k, v := range rc.checks {
		checks[k] = v
	}
	rc.mu.RUnlock()

	result := ReadinessStatus{
		Status:  "ready",
		Version: rc.version,
		Checks:  make(map[string]CheckStatus, len(checks)),
	}

	hasFail := false
	hasDegraded := false

	for name, check := range checks {
		cs := check()
		result.Checks[name] = cs
		switch cs.Status {
		case "fail":
			hasFail = true
		case "degraded":
			hasDegraded = true
		}
	}

	if hasFail {
		result.Status = "not_ready"
	} else if hasDegraded {
		result.Status = "degraded"
	}

	if !rc.details {
		result.Checks = nil
	}

	return result
}

// Handler returns an HTTP handler for readiness probes.
func (rc *ReadinessChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := rc.Check()
		w.Header().Set("Content-Type", "application/json")
		if status.Status == "not_ready" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	}
}
