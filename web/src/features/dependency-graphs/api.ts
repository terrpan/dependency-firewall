import { useQuery } from '@tanstack/react-query'
import type { DependencyGraph, DependencyGraphRoot } from '../../lib/api/index.ts'
import { useTenant } from '../tenant/useTenant.ts'
import { useTenantControlPlaneApi } from '../tenant/useTenantControlPlaneApi.ts'

export function useDependencyGraphRoots() {
  const api = useTenantControlPlaneApi()
  const { tenantId } = useTenant()
  return useQuery({
    queryKey: ['dependency-graph-roots', tenantId],
    enabled: Boolean(tenantId),
    queryFn: ({ signal }) => api.dependencyGraphs.list({ signal, limit: 200 }),
  })
}

export function useDependencyGraph(rootId: string | null) {
  const api = useTenantControlPlaneApi()
  const { tenantId } = useTenant()
  return useQuery({
    queryKey: ['dependency-graph', tenantId, rootId],
    enabled: Boolean(tenantId && rootId),
    queryFn: ({ signal }) => api.dependencyGraphs.get(rootId ?? '', { signal }),
  })
}

export function normalizeGraphRoots(roots: DependencyGraphRoot[] | null | undefined): DependencyGraphRoot[] {
  return Array.isArray(roots) ? roots : []
}

export function normalizeGraph(graph: DependencyGraph | null | undefined): DependencyGraph | null {
  return graph && Array.isArray(graph.nodes) && Array.isArray(graph.edges) ? graph : null
}
