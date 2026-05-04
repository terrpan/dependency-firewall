function readEnv(key: keyof ImportMetaEnv, fallback: string) {
  const value = import.meta.env[key]

  if (!value) {
    return fallback
  }

  const trimmedValue = value.trim()
  return trimmedValue || fallback
}

function normalizeDevTelemetryExporterUrl(value: string) {
  if (!import.meta.env.DEV) {
    return value
  }

  try {
    const url = new URL(value)
    if (url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
      return value
    }

    return `/otlp${url.pathname}`
  } catch {
    return value
  }
}

function readBooleanEnv(key: keyof ImportMetaEnv, fallback: boolean) {
  const value = import.meta.env[key]
  if (!value) {
    return fallback
  }

  switch (value.trim().toLowerCase()) {
    case '1':
    case 'true':
    case 'yes':
    case 'on':
      return true
    case '0':
    case 'false':
    case 'no':
    case 'off':
      return false
    default:
      return fallback
  }
}

function readNumberEnv(key: keyof ImportMetaEnv, fallback: number) {
  const value = import.meta.env[key]
  if (!value) {
    return fallback
  }

  const parsed = Number(value.trim())
  return Number.isFinite(parsed) ? parsed : fallback
}

function trimTrailingSlash(value: string) {
  if (value === '/') {
    return ''
  }

  return value.replace(/\/+$/, '')
}

function stripControlPlanePath(value: string) {
  const trimmedValue = trimTrailingSlash(value)
  const rootValue = trimmedValue.replace(/\/api\/v1$/, '')
  return rootValue || ''
}

export function joinUrlPath(base: string, path: string) {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  const normalizedBase = trimTrailingSlash(base)

  if (!normalizedBase) {
    return normalizedPath
  }

  return `${normalizedBase}${normalizedPath}`
}

export const controlPlaneBaseUrl = trimTrailingSlash(readEnv('VITE_API_BASE_URL', '/api/v1'))
export const controlPlaneRootUrl = stripControlPlanePath(controlPlaneBaseUrl)
export const firewallRootUrl = trimTrailingSlash(
  readEnv(
    'VITE_FIREWALL_ROOT_URL',
    controlPlaneRootUrl ||
      (import.meta.env.DEV
        ? 'http://localhost:8080'
        : typeof window !== 'undefined'
          ? window.location.origin
          : 'http://localhost:8080'),
  ),
)
export const docsUrl = readEnv('VITE_DOCS_URL', joinUrlPath(controlPlaneRootUrl, '/api/docs'))
export const openApiUrl = readEnv('VITE_OPENAPI_URL', joinUrlPath(controlPlaneRootUrl, '/api/openapi.json'))
export const telemetryEnabled = readBooleanEnv('VITE_OTEL_ENABLED', false)
export const telemetryExporterUrl = readEnv(
  'VITE_OTEL_EXPORTER_URL',
  import.meta.env.DEV ? '/otlp/v1/traces' : 'http://localhost:4318/v1/traces',
)
export const normalizedTelemetryExporterUrl = normalizeDevTelemetryExporterUrl(telemetryExporterUrl)
export const telemetryServiceName = readEnv('VITE_OTEL_SERVICE_NAME', 'dependency-firewall-web')
export const telemetrySampleRatio = Math.min(1, Math.max(0, readNumberEnv('VITE_OTEL_SAMPLE_RATIO', 1)))
