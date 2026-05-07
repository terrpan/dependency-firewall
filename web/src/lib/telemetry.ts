import { context, propagation, trace, SpanStatusCode, type Attributes, type Span } from '@opentelemetry/api'

const tracerName = 'dependency-firewall-web'

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
