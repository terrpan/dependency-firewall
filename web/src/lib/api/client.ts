import { controlPlaneBaseUrl, controlPlaneRootUrl, joinUrlPath } from '../config.ts'
import { ApiError, getErrorMessage } from './error.ts'
import type {
  CacheClearResult,
  CreatePolicyRequest,
  CreateTenantRequest,
  CreateUpstreamRequest,
  Evaluation,
  Health,
  Policy,
  PolicyImportBody,
  PolicyImportContentType,
  PolicyImportResult,
  PolicyTypeDescriptor,
  PolicyUpsertInput,
  PolicyVersion,
  RollbackPolicyRequest,
  Tenant,
  UpdatePolicyRequest,
  UpdateTenantRequest,
  UpdateUpstreamRequest,
  Upstream,
} from './types.ts'

type RequestHeaders = HeadersInit | undefined

type QueryValue = string | number | boolean | null | undefined

type RequestOptions = {
  signal?: AbortSignal
  headers?: RequestHeaders
  tenantId?: string
}

type PolicyRemoveOptions = RequestOptions & {
  force?: boolean
}

type JsonRequestOptions<TBody> = RequestOptions & {
  body?: TBody
  query?: Record<string, QueryValue>
}

export type ControlPlaneApiOptions = {
  baseUrl?: string
  rootUrl?: string
  fetch?: typeof globalThis.fetch
  getTenantId?: () => string | undefined
  getSessionHeaders?: () => RequestHeaders
  getHeaders?: () => RequestHeaders
}

type RequestScope = 'control-plane' | 'root'

type InternalRequestOptions<TBody> = JsonRequestOptions<TBody> & {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  path: string
  scope?: RequestScope
  contentType?: string
  accept?: string
  tenantScoped?: boolean
}

function trimTrailingSlash(value: string): string {
  if (value === '/') {
    return ''
  }

  return value.replace(/\/+$/, '')
}

function withLeadingSlash(path: string): string {
  return path.startsWith('/') ? path : `/${path}`
}

function mergeHeaders(...sources: RequestHeaders[]): Headers {
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

function buildRequestUrl(baseUrl: string, path: string, query?: Record<string, QueryValue>): string {
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

async function readResponseBody(response: Response): Promise<unknown> {
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

export function createControlPlaneApi(options: ControlPlaneApiOptions = {}) {
  const fetcher = options.fetch ?? globalThis.fetch
  const baseUrl = trimTrailingSlash(options.baseUrl ?? controlPlaneBaseUrl)
  const rootUrl = trimTrailingSlash(options.rootUrl ?? controlPlaneRootUrl)

  async function request<TResponse, TBody = undefined>({
    accept = 'application/json',
    body,
    contentType,
    headers,
    method,
    path,
    query,
    scope = 'control-plane',
    signal,
    tenantId,
    tenantScoped = false,
  }: InternalRequestOptions<TBody>): Promise<TResponse> {
    const requestBaseUrl = scope === 'root' ? rootUrl : baseUrl
    const url = buildRequestUrl(requestBaseUrl, path, query)
    const requestHeaders = mergeHeaders(options.getSessionHeaders?.(), options.getHeaders?.(), headers)

    if (accept) {
      requestHeaders.set('Accept', accept)
    }

    const resolvedTenantId = tenantId ?? options.getTenantId?.()
    if (tenantScoped && resolvedTenantId) {
      requestHeaders.set('X-Tenant-ID', resolvedTenantId)
    }

    let requestBody: BodyInit | undefined
    if (body !== undefined) {
      if (contentType === 'application/json') {
        requestBody = JSON.stringify(body)
      } else {
        requestBody = body as BodyInit
      }
    }

    if (contentType && requestBody !== undefined) {
      requestHeaders.set('Content-Type', contentType)
    }

    let response: Response
    try {
      response = await fetcher(url, {
        method,
        headers: requestHeaders,
        body: requestBody,
        signal,
      })
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error
      }

      throw new ApiError({
        message: error instanceof Error ? error.message : 'Request failed',
        status: 0,
        statusText: 'network_error',
        url,
        cause: error,
      })
    }

    if (!response.ok) {
      const responseBody = await readResponseBody(response)
      throw new ApiError({
        message: getErrorMessage(responseBody, `Request failed with status ${response.status}`),
        status: response.status,
        statusText: response.statusText,
        url,
        body: responseBody,
      })
    }

    if (response.status === 204) {
      return undefined as TResponse
    }

    const responseBody = await readResponseBody(response)
    return responseBody as TResponse
  }

  return {
    health: {
      get(options?: RequestOptions) {
        return request<Health>({
          method: 'GET',
          path: '/healthz',
          scope: 'root',
          ...options,
        })
      },
    },
    tenants: {
      list(options?: RequestOptions) {
        return request<Tenant[]>({ method: 'GET', path: '/tenants', ...options })
      },
      create(body: CreateTenantRequest, options?: RequestOptions) {
        return request<Tenant, CreateTenantRequest>({
          method: 'POST',
          path: '/tenants',
          body,
          contentType: 'application/json',
          ...options,
        })
      },
      get(id: string, options?: RequestOptions) {
        return request<Tenant>({ method: 'GET', path: `/tenants/${id}`, ...options })
      },
      update(id: string, body: UpdateTenantRequest, options?: RequestOptions) {
        return request<Tenant, UpdateTenantRequest>({
          method: 'PUT',
          path: `/tenants/${id}`,
          body,
          contentType: 'application/json',
          ...options,
        })
      },
      remove(id: string, options?: RequestOptions) {
        return request<void>({ method: 'DELETE', path: `/tenants/${id}`, ...options })
      },
    },
    upstreams: {
      list(options?: RequestOptions) {
        return request<Upstream[]>({
          method: 'GET',
          path: '/upstreams',
          tenantScoped: true,
          ...options,
        })
      },
      create(body: CreateUpstreamRequest, options?: RequestOptions) {
        return request<Upstream, CreateUpstreamRequest>({
          method: 'POST',
          path: '/upstreams',
          body,
          contentType: 'application/json',
          tenantScoped: true,
          ...options,
        })
      },
      get(id: string, options?: RequestOptions) {
        return request<Upstream>({
          method: 'GET',
          path: `/upstreams/${id}`,
          tenantScoped: true,
          ...options,
        })
      },
      update(id: string, body: UpdateUpstreamRequest, options?: RequestOptions) {
        return request<Upstream, UpdateUpstreamRequest>({
          method: 'PUT',
          path: `/upstreams/${id}`,
          body,
          contentType: 'application/json',
          tenantScoped: true,
          ...options,
        })
      },
      remove(id: string, options?: RequestOptions) {
        return request<void>({
          method: 'DELETE',
          path: `/upstreams/${id}`,
          tenantScoped: true,
          ...options,
        })
      },
    },
    policies: {
      list(options?: RequestOptions) {
        return request<Policy[]>({ method: 'GET', path: '/policies', tenantScoped: true, ...options })
      },
      create(body: PolicyUpsertInput, options?: RequestOptions) {
        return request<Policy, CreatePolicyRequest>({
          method: 'POST',
          path: '/policies',
          body: body as CreatePolicyRequest,
          contentType: 'application/json',
          tenantScoped: true,
          ...options,
        })
      },
      get(id: string, options?: RequestOptions) {
        return request<Policy>({
          method: 'GET',
          path: `/policies/${id}`,
          tenantScoped: true,
          ...options,
        })
      },
      update(id: string, body: PolicyUpsertInput, options?: RequestOptions) {
        return request<Policy, UpdatePolicyRequest>({
          method: 'PUT',
          path: `/policies/${id}`,
          body: body as UpdatePolicyRequest,
          contentType: 'application/json',
          tenantScoped: true,
          ...options,
        })
      },
      remove(id: string, options?: PolicyRemoveOptions) {
        const { force, ...requestOptions } = options ?? {}
        return request<void>({
          method: 'DELETE',
          path: `/policies/${id}`,
          query: { force },
          tenantScoped: true,
          ...requestOptions,
        })
      },
      listVersions(id: string, options?: RequestOptions) {
        return request<PolicyVersion[]>({
          method: 'GET',
          path: `/policies/${id}/versions`,
          tenantScoped: true,
          ...options,
        })
      },
      rollback(id: string, body: RollbackPolicyRequest, options?: RequestOptions) {
        return request<Policy, RollbackPolicyRequest>({
          method: 'POST',
          path: `/policies/${id}/rollback`,
          body,
          contentType: 'application/json',
          tenantScoped: true,
          ...options,
        })
      },
      listTypes(options?: RequestOptions) {
        return request<PolicyTypeDescriptor[]>({ method: 'GET', path: '/policy-types', ...options })
      },
      importDocument(
        body: PolicyImportBody,
        options?: RequestOptions & { contentType?: PolicyImportContentType },
      ) {
        const contentType = options?.contentType ?? (typeof body === 'string' || body instanceof Uint8Array
          ? 'application/x-yaml'
          : 'application/json')

        return request<PolicyImportResult, PolicyImportBody>({
          method: 'POST',
          path: '/policies/import',
          body,
          contentType,
          tenantScoped: true,
          ...options,
        })
      },
    },
    evaluations: {
      list(options?: RequestOptions & { limit?: number; offset?: number; search?: string }) {
        return request<Evaluation[]>({
          method: 'GET',
          path: '/evaluations',
          query: {
            limit: options?.limit,
            offset: options?.offset,
            search: options?.search,
          },
          tenantScoped: true,
          ...options,
        })
      },
    },
    cache: {
      clearDecisions(options?: RequestOptions) {
        return request<CacheClearResult>({
          method: 'DELETE',
          path: '/cache/decisions',
          tenantScoped: true,
          ...options,
        })
      },
      clearMetadata(options?: RequestOptions) {
        return request<CacheClearResult>({
          method: 'DELETE',
          path: '/cache/metadata',
          tenantScoped: true,
          ...options,
        })
      },
    },
    urls: {
      controlPlane(path = '/') {
        return buildRequestUrl(baseUrl, path)
      },
      root(path = '/') {
        return buildRequestUrl(rootUrl, path)
      },
      docs() {
        return joinUrlPath(rootUrl, '/api/docs')
      },
      openApi() {
        return joinUrlPath(rootUrl, '/api/openapi.json')
      },
    },
  }
}

export type ControlPlaneApi = ReturnType<typeof createControlPlaneApi>

export const controlPlaneApi = createControlPlaneApi()
