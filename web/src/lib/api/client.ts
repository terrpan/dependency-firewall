import { controlPlaneBaseUrl, controlPlaneRootUrl, joinUrlPath } from '../config.ts'
import { ApiError, getErrorMessage } from './error.ts'
import { injectTraceContext, recordSpanError, startSpan } from '../telemetry.ts'
import {
  buildRequestUrl,
  mergeHeaders,
  normalizeTracePath,
  readResponseBody,
  trimTrailingSlash,
  type QueryValue,
  type RequestHeaders,
} from './request.ts'
import type {
  CacheClearResult,
  DependencyGraph,
  DependencyGraphRoot,
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
  ApproveProxyEnrollmentRequest,
  ProxyEnrollment,
  ProxyEnrollmentConfiguration,
  ProxyInstallation,
  RenameProxyInstallationRequest,
  ResolveProxyEnrollmentRequest,
} from './types.ts'

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
  getAccessToken?: () => Promise<string | null>
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
    const accessToken = await options.getAccessToken?.()
    const requestHeaders = mergeHeaders(options.getHeaders?.(), headers)
    if (accessToken) {
      requestHeaders.set('Authorization', `Bearer ${accessToken}`)
    }
    const resolvedTenantId = tenantId ?? options.getTenantId?.()
    const normalizedPath = normalizeTracePath(path)
    const span = startSpan(`${method} ${normalizedPath}`, {
      'http.method': method,
      'http.route': normalizedPath,
      'request.scope': scope,
      'request.tenant_scoped': tenantScoped,
      ...(resolvedTenantId ? { 'tenant.id': resolvedTenantId } : {}),
      ...(method === 'GET' ? {} : { 'ui.action.type': 'mutation' }),
    })

    if (accept) {
      requestHeaders.set('Accept', accept)
    }

    if (tenantScoped && resolvedTenantId) {
      requestHeaders.set('X-Tenant-ID', resolvedTenantId)
    }
    injectTraceContext(requestHeaders, span)

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
        span.setStatus({ code: 1 })
        span.end()
        throw error
      }

      recordSpanError(span, error, 'Request failed')
      span.end()
      throw new ApiError({
        message: error instanceof Error ? error.message : 'Request failed',
        status: 0,
        statusText: 'network_error',
        url,
        cause: error,
      })
    }
    span.setAttribute('http.status_code', response.status)

    if (!response.ok) {
      const responseBody = await readResponseBody(response)
      recordSpanError(
        span,
        responseBody instanceof Error ? responseBody : undefined,
        `Request failed with status ${response.status}`,
      )
      span.end()
      throw new ApiError({
        message: getErrorMessage(responseBody, `Request failed with status ${response.status}`),
        status: response.status,
        statusText: response.statusText,
        url,
        body: responseBody,
      })
    }

    if (response.status === 204) {
      span.end()
      return undefined as TResponse
    }

    const responseBody = await readResponseBody(response)
    span.end()
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
    proxyEnrollments: {
      configuration(options?: RequestOptions) {
        return request<ProxyEnrollmentConfiguration>({
          method: 'GET',
          path: '/proxy-enrollment-configuration',
          ...options,
        })
      },
      resolve(body: ResolveProxyEnrollmentRequest, options?: RequestOptions) {
        return request<ProxyEnrollment, ResolveProxyEnrollmentRequest>({
          method: 'POST',
          path: '/proxy-enrollments/resolve',
          body,
          contentType: 'application/json',
          ...options,
        })
      },
      approve(id: string, body: ApproveProxyEnrollmentRequest, options?: RequestOptions) {
        return request<ProxyEnrollment, ApproveProxyEnrollmentRequest>({
          method: 'POST',
          path: `/proxy-enrollments/${id}/approve`,
          body,
          contentType: 'application/json',
          ...options,
        })
      },
      deny(id: string, userCode: string, options?: RequestOptions) {
        return request<void, { user_code: string }>({
          method: 'POST',
          path: `/proxy-enrollments/${id}/deny`,
          body: { user_code: userCode },
          contentType: 'application/json',
          ...options,
        })
      },
    },
    proxyInstallations: {
      list(tenantId: string, options?: RequestOptions) {
        return request<ProxyInstallation[]>({
          method: 'GET',
          path: `/tenants/${tenantId}/proxy-installations`,
          ...options,
        })
      },
      get(tenantId: string, id: string, options?: RequestOptions) {
        return request<ProxyInstallation>({
          method: 'GET',
          path: `/tenants/${tenantId}/proxy-installations/${id}`,
          ...options,
        })
      },
      rename(tenantId: string, id: string, body: RenameProxyInstallationRequest, options?: RequestOptions) {
        return request<ProxyInstallation, RenameProxyInstallationRequest>({
          method: 'PUT',
          path: `/tenants/${tenantId}/proxy-installations/${id}`,
          body,
          contentType: 'application/json',
          ...options,
        })
      },
      revoke(tenantId: string, id: string, options?: RequestOptions) {
        return request<ProxyInstallation>({
          method: 'DELETE',
          path: `/tenants/${tenantId}/proxy-installations/${id}`,
          ...options,
        })
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
          body: body,
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
          body: body,
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
      importDocument(body: PolicyImportBody, options?: RequestOptions & { contentType?: PolicyImportContentType }) {
        const contentType =
          options?.contentType ??
          (typeof body === 'string' || body instanceof Uint8Array ? 'application/x-yaml' : 'application/json')

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
    dependencyGraphs: {
      list(options?: RequestOptions & { limit?: number }) {
        return request<DependencyGraphRoot[]>({
          method: 'GET',
          path: '/dependency-graphs',
          query: { limit: options?.limit },
          tenantScoped: true,
          ...options,
        })
      },
      get(id: string, options?: RequestOptions) {
        return request<DependencyGraph>({
          method: 'GET',
          path: `/dependency-graphs/${id}`,
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
