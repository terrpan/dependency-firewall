function readEnv(key: keyof ImportMetaEnv, fallback: string) {
  const value = import.meta.env[key]

  if (!value) {
    return fallback
  }

  const trimmedValue = value.trim()
  return trimmedValue || fallback
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
