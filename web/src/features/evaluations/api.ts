import { useQuery } from '@tanstack/react-query'
import type { Evaluation } from '../../lib/api/index.ts'
import { useTenant } from '../tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../tenant/useTenantControlPlaneApi.ts'

export const dashboardEvaluationsLimit = 12
export const evaluationsPageSize = 25

function normalizeEvaluations(response: Evaluation[] | null | undefined): Evaluation[] {
  return Array.isArray(response) ? response : []
}

export function useRecentEvaluations(limit = dashboardEvaluationsLimit) {
  const api = useTenantControlPlaneApi()
  const { tenantId } = useTenant()

  return useQuery({
    queryKey: ['evaluations', tenantId, 'recent', limit],
    enabled: Boolean(tenantId),
    queryFn: async ({ signal }) =>
      normalizeEvaluations((await api.evaluations.list({ signal, limit })) as Evaluation[] | null),
  })
}

export function useEvaluationsPage(limit: number, offset: number, search: string) {
  const api = useTenantControlPlaneApi()
  const { tenantId } = useTenant()

  return useQuery({
    queryKey: ['evaluations', tenantId, limit, offset, search],
    enabled: Boolean(tenantId),
    queryFn: async ({ signal }) =>
      normalizeEvaluations(
        (await api.evaluations.list({
          signal,
          limit,
          offset,
          search,
        })) as Evaluation[] | null,
      ),
  })
}
