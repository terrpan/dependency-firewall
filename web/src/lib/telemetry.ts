import { context, propagation, trace, SpanStatusCode, type Attributes, type Span } from '@opentelemetry/api'
import { W3CTraceContextPropagator } from '@opentelemetry/core'
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-proto'
import { resourceFromAttributes } from '@opentelemetry/resources'
import {
  BatchSpanProcessor,
  ParentBasedSampler,
  SimpleSpanProcessor,
  TraceIdRatioBasedSampler,
} from '@opentelemetry/sdk-trace-base'
import { WebTracerProvider } from '@opentelemetry/sdk-trace-web'
import {
  telemetryEnabled,
  normalizedTelemetryExporterUrl,
  telemetrySampleRatio,
  telemetryServiceName,
} from './config.ts'

const tracerName = 'dependency-firewall-web'

let telemetryInitialized = false

export function initializeTelemetry() {
  if (telemetryInitialized || !telemetryEnabled) {
    return
  }

  const exporter = new OTLPTraceExporter({
    url: normalizedTelemetryExporterUrl,
  })

  const provider = new WebTracerProvider({
    resource: resourceFromAttributes({
      'service.name': telemetryServiceName,
    }),
    sampler: new ParentBasedSampler({
      root: new TraceIdRatioBasedSampler(telemetrySampleRatio),
    }),
    spanProcessors: [import.meta.env.DEV ? new SimpleSpanProcessor(exporter) : new BatchSpanProcessor(exporter)],
  })

  provider.register({
    propagator: new W3CTraceContextPropagator(),
  })

  telemetryInitialized = true
}

export function getTracer() {
  return trace.getTracer(tracerName)
}

export function startSpan(name: string, attributes?: Attributes): Span {
  return getTracer().startSpan(name, {
    attributes,
  })
}

export function injectTraceContext(headers: Headers, span: Span) {
  const carrierContext = trace.setSpan(context.active(), span)
  propagation.inject(carrierContext, headers, {
    set(carrier, key, value) {
      carrier.set(key, value)
    },
  })
}

export function recordSpanError(span: Span, error: unknown, fallbackMessage: string) {
  const message = error instanceof Error ? error.message : fallbackMessage
  if (error instanceof Error) {
    span.recordException(error)
  }
  span.setStatus({
    code: SpanStatusCode.ERROR,
    message,
  })
}
