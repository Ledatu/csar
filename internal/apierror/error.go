// Package apierror re-exports the shared CSAR API error envelope from csar-core.
// Local code continues to import this package unchanged.
package apierror

import (
	core "github.com/ledatu/csar-core/apierror"
)

// Re-export types.
type Response = core.Response

// Re-export error codes.
const (
	CodeRouteNotFound     = core.CodeRouteNotFound
	CodeAccessDenied      = core.CodeAccessDenied
	CodeAuthFailed        = core.CodeAuthFailed
	CodeThrottled         = core.CodeThrottled
	CodeCircuitOpen       = core.CodeCircuitOpen
	CodeBackpressure      = core.CodeBackpressure
	CodeUpstreamError     = core.CodeUpstreamError
	CodeNoHealthyUpstream = core.CodeNoHealthyUpstream
	CodeTenantNotFound    = core.CodeTenantNotFound
	CodeResponseTooLarge  = core.CodeResponseTooLarge
	CodeSecurityError     = core.CodeSecurityError
)

// CodeThrottleUnavailable means the rate-limit backend failed, so the router
// could not decide whether the request was within its limit.
const CodeThrottleUnavailable = "throttle_unavailable"

// Re-export constructors.
var New = core.New
