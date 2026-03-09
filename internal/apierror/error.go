// Package apierror provides a standardized error response format for all
// CSAR-originated error responses. Every error body follows the same JSON
// schema so SDK clients can parse them uniformly.
package apierror

import (
	"encoding/json"
	"net/http"
)

// Standard error codes returned by CSAR.
const (
	CodeRouteNotFound     = "route_not_found"
	CodeAccessDenied      = "access_denied"
	CodeAuthFailed        = "auth_failed"
	CodeThrottled         = "throttled"
	CodeCircuitOpen       = "circuit_open"
	CodeBackpressure      = "backpressure"
	CodeUpstreamError     = "upstream_error"
	CodeNoHealthyUpstream = "no_healthy_upstream"
	CodeTenantNotFound    = "tenant_not_found"
	CodeResponseTooLarge  = "response_too_large"
	CodeSecurityError     = "security_error"
)

// Response is the standard JSON error body for all CSAR error responses.
type Response struct {
	Code         string `json:"code"`
	Status       int    `json:"status"`
	Message      string `json:"message"`
	RetryAfterMS *int64 `json:"retry_after_ms,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// Write serializes the error response as JSON to the ResponseWriter.
func (r *Response) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.Status)
	json.NewEncoder(w).Encode(r)
}

// New creates a Response with the given code, HTTP status, and message.
func New(code string, status int, message string) *Response {
	return &Response{Code: code, Status: status, Message: message}
}

// WithRetryAfterMS sets the retry_after_ms field.
func (r *Response) WithRetryAfterMS(ms int64) *Response {
	r.RetryAfterMS = &ms
	return r
}

// WithRequestID sets the request_id field.
func (r *Response) WithRequestID(id string) *Response {
	r.RequestID = id
	return r
}

// WithDetail sets the detail field.
func (r *Response) WithDetail(detail string) *Response {
	r.Detail = detail
	return r
}
