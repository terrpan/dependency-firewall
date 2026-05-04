package telemetry

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"github.com/danielterry/dependency-firewall/internal/config"
)

// Provider owns the runtime OpenTelemetry provider lifecycle.
type Provider struct {
	shutdown func(context.Context) error
}

// Start initializes global OpenTelemetry tracing state for one runtime process.
func Start(ctx context.Context, cfg config.TelemetryConfig, serviceName, version, commit, buildTime string) (*Provider, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled {
		return &Provider{shutdown: func(context.Context) error { return nil }}, nil
	}

	traceOptions, err := traceProviderOptions(ctx, cfg)
	if err != nil {
		return nil, err
	}

	resource, err := resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
			attribute.String("service.commit", commit),
			attribute.String("service.build_time", buildTime),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("building telemetry resource: %w", err)
	}

	options := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(resource),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	}
	options = append(options, traceOptions...)

	tracerProvider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(tracerProvider)

	return &Provider{
		shutdown: tracerProvider.Shutdown,
	}, nil
}

// Shutdown flushes and closes telemetry exporters.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

func traceProviderOptions(ctx context.Context, cfg config.TelemetryConfig) ([]sdktrace.TracerProviderOption, error) {
	options := make([]sdktrace.TracerProviderOption, 0, 2)

	if strings.TrimSpace(cfg.Endpoint) != "" {
		traceExporter, err := newTraceExporter(ctx, cfg)
		if err != nil {
			return nil, err
		}
		options = append(options, sdktrace.WithBatcher(traceExporter))
	}

	if cfg.Stdout {
		stdoutExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("creating stdout trace exporter: %w", err)
		}
		options = append(options, sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(stdoutExporter)))
	}

	if len(options) == 0 {
		return nil, fmt.Errorf("telemetry is enabled but no trace exporters are configured")
	}

	return options, nil
}

func newTraceExporter(ctx context.Context, cfg config.TelemetryConfig) (sdktrace.SpanExporter, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Protocol)) {
	case "", "grpc":
		options := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpointURL(cfg.Endpoint),
		}
		if cfg.Insecure {
			options = append(options, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			options = append(options, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		exporter, err := otlptracegrpc.New(ctx, options...)
		if err != nil {
			return nil, fmt.Errorf("creating grpc trace exporter: %w", err)
		}
		return exporter, nil
	case "http/protobuf":
		options := []otlptracehttp.Option{
			otlptracehttp.WithEndpointURL(cfg.Endpoint),
		}
		if cfg.Insecure {
			options = append(options, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			options = append(options, otlptracehttp.WithHeaders(cfg.Headers))
		}
		exporter, err := otlptracehttp.New(ctx, options...)
		if err != nil {
			return nil, fmt.Errorf("creating http trace exporter: %w", err)
		}
		return exporter, nil
	default:
		return nil, fmt.Errorf("unsupported telemetry protocol %q", cfg.Protocol)
	}
}
