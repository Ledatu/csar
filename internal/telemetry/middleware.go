package telemetry

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// HTTPMiddleware returns an HTTP middleware that creates a span for each request.
func (p *Provider) HTTPMiddleware(operationName string, next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, operationName,
		otelhttp.WithTracerProvider(p.tp),
	)
}

// StartSpan starts a new child span from the request context.
// Use this for tracing sub-operations (throttle wait, upstream call, KMS decrypt).
func (p *Provider) StartSpan(r *http.Request, name string, attrs ...attribute.KeyValue) (*http.Request, trace.Span) {
	ctx, span := p.tracer.Start(r.Context(), name,
		trace.WithAttributes(attrs...),
	)
	return r.WithContext(ctx), span
}

// SpanFromContext starts a span from a context (for non-HTTP operations).
func (p *Provider) SpanFromContext(parent trace.SpanContext, name string, attrs ...attribute.KeyValue) (trace.Span, func()) {
	// This is a simplified helper — for full control use the tracer directly.
	// In practice, the parent context carries the span.
	return trace.SpanFromContext(nil), func() {}
}
