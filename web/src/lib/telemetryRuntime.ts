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
  normalizedTelemetryExporterUrl,
  telemetryEnabled,
  telemetrySampleRatio,
  telemetryServiceName,
} from './config.ts'

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
