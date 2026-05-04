package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// WrapLogger enriches context-aware log records with trace and span IDs.
func WrapLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return nil
	}
	return slog.New(&traceLogHandler{next: logger.Handler()})
}

type traceLogHandler struct {
	next slog.Handler
}

func (h *traceLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *traceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return h.next.Handle(ctx, record)
	}

	enriched := record.Clone()
	enriched.AddAttrs(
		slog.String("trace_id", spanContext.TraceID().String()),
		slog.String("span_id", spanContext.SpanID().String()),
	)

	return h.next.Handle(ctx, enriched)
}

func (h *traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceLogHandler{next: h.next.WithAttrs(attrs)}
}

func (h *traceLogHandler) WithGroup(name string) slog.Handler {
	return &traceLogHandler{next: h.next.WithGroup(name)}
}
