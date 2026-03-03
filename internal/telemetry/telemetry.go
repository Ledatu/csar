package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds telemetry configuration.
type Config struct {
	// ServiceName is the name reported to the tracing backend.
	ServiceName string

	// ServiceVersion is the version reported.
	ServiceVersion string

	// OTLPEndpoint is the gRPC endpoint of the OTLP collector (e.g. "localhost:4317").
	// Leave empty to disable OTLP export (useful for dev with noop tracer).
	OTLPEndpoint string

	// SampleRate is the fraction of traces to sample (0.0 = none, 1.0 = all).
	SampleRate float64

	// Insecure disables TLS for the OTLP connection.
	Insecure bool
}

// Provider wraps an OpenTelemetry TracerProvider with convenience methods.
type Provider struct {
	tp     *sdktrace.TracerProvider
	tracer trace.Tracer
}

// Init initializes the OpenTelemetry tracing pipeline.
// Returns a Provider that should be shut down with Close() on application exit.
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "csar"
	}
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0 // Default: sample everything
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
			semconv.ServiceVersionKey.String(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating resource: %w", err)
	}

	var opts []sdktrace.TracerProviderOption
	opts = append(opts,
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
	)

	// Set up OTLP exporter if endpoint is configured
	if cfg.OTLPEndpoint != "" {
		exporterOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
		}
		if cfg.Insecure {
			exporterOpts = append(exporterOpts, otlptracegrpc.WithInsecure())
		}

		exporter, err := otlptracegrpc.New(ctx, exporterOpts...)
		if err != nil {
			return nil, fmt.Errorf("creating OTLP exporter: %w", err)
		}

		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	tp := sdktrace.NewTracerProvider(opts...)

	// Set global providers
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		tp:     tp,
		tracer: tp.Tracer(cfg.ServiceName),
	}, nil
}

// Tracer returns the configured tracer instance.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Close shuts down the tracer provider, flushing any pending spans.
func (p *Provider) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.tp.Shutdown(ctx)
}

// Noop returns a Provider with a no-op tracer for testing and development.
func Noop() *Provider {
	tp := sdktrace.NewTracerProvider()
	return &Provider{
		tp:     tp,
		tracer: tp.Tracer("csar-noop"),
	}
}
