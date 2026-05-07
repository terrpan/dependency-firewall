// Request utilities centralize URL, header, and response parsing helpers for API clients.
export type RequestHeaders = HeadersInit | undefined

export type QueryValue = string | number | boolean | null | undefined

export function trimTrailingSlash(value: string): string {
  if (value === '/') {
    return ''
  }

  return value.replace(/\/+$/, '')
}

function withLeadingSlash(path: string): string {
  return path.startsWith('/') ? path : `/${path}`
}

export function mergeHeaders(...sources: RequestHeaders[]): Headers {
  const headers = new Headers()

  for (const source of sources) {
    if (!source) {
      continue
    }

    const nextHeaders = new Headers(source)
    nextHeaders.forEach((value, key) => {
      headers.set(key, value)
    })
  }

  return headers
}

export function buildRequestUrl(
  baseUrl: string,
  path: string,
  query?: Record<string, QueryValue>,
): string {
  const url = new URL(`${trimTrailingSlash(baseUrl)}${withLeadingSlash(path)}`, 'http://localhost')

  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === '') {
      continue
    }

    url.searchParams.set(key, String(value))
  }

  if (!baseUrl.startsWith('http://') && !baseUrl.startsWith('https://')) {
    return `${url.pathname}${url.search}`
  }

  return url.toString()
}

export function normalizeTracePath(path: string): string {
  const segments = path.split('/').filter(Boolean)

  return `/${segments
    .map((segment, index) => {
      const previous = segments[index - 1]
      if (previous === 'tenants' || previous === 'upstreams' || previous === 'policies') {
        return ':id'
      }
      if (/^[0-9a-f]{8,}$/i.test(segment) || /^[0-9a-f]{8,}-[0-9a-f-]+$/i.test(segment)) {
        return ':id'
      }
      return segment
    })
    .join('/')}`
}

export async function readResponseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? ''

  if (contentType.includes('application/json')) {
    try {
      return (await response.json()) as unknown
    } catch {
      return undefined
    }
  }

  const text = await response.text()
  return text || undefined
}
