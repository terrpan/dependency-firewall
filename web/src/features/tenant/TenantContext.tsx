import { useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useState, type PropsWithChildren } from 'react'
import { useAuth } from '../auth/useAuth.ts'
import { useSessionControlPlaneApi } from '../auth/useSessionControlPlaneApi.ts'
import { fetchTenants, type TenantOption } from './api.ts'
import { TenantContext, tenantStorageKey, type TenantStatus } from './context.ts'

const emptyTenants: readonly TenantOption[] = []

function getInitialTenantId() {
  if (typeof window === 'undefined') {
    return null
  }

  const storedTenantId = window.localStorage.getItem(tenantStorageKey)?.trim()
  return storedTenantId || null
}

function getTenantStatus(
  activeTenantId: string | null,
  isPending: boolean,
  isError: boolean,
  tenantCount: number,
): TenantStatus {
  if (activeTenantId) {
    return 'ready'
  }

  if (isPending) {
    return 'loading'
  }

  if (isError) {
    return 'error'
  }

  if (tenantCount === 0) {
    return 'empty'
  }

  return 'loading'
}

export function TenantProvider({ children }: PropsWithChildren) {
  const api = useSessionControlPlaneApi()
  const { session, status: authStatus } = useAuth()
  const [storedTenantId, setStoredTenantId] = useState<string | null>(getInitialTenantId)

  const { data, error, isError, isPending, refetch } = useQuery({
    queryKey: ['tenants', authStatus, session?.user?.id ?? null],
    queryFn: () => fetchTenants(api),
  })

  const tenants = data ?? emptyTenants

  const activeTenant = useMemo(
    () => tenants.find((tenant) => tenant.id === storedTenantId) ?? tenants[0] ?? null,
    [storedTenantId, tenants],
  )

  const tenantId = activeTenant?.id ?? null

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }

    if (!tenantId) {
      window.localStorage.removeItem(tenantStorageKey)
      return
    }

    window.localStorage.setItem(tenantStorageKey, tenantId)
  }, [tenantId])

  const handleTenantChange = useCallback((nextTenantId: string) => {
    setStoredTenantId(nextTenantId)
  }, [])

  const reloadTenants = useCallback(async () => {
    await refetch()
  }, [refetch])

  const status = getTenantStatus(tenantId, isPending, isError, tenants.length)
  const errorMessage =
    error instanceof Error ? error.message : 'Unable to load tenants right now.'

  const value = useMemo(
    () => ({
      tenantId,
      setTenantId: handleTenantChange,
      tenants,
      activeTenant,
      reloadTenants,
      status,
      hasTenants: tenants.length > 0,
      isLoading: status === 'loading',
      isError: status === 'error',
      errorMessage: status === 'error' ? errorMessage : null,
    }),
    [activeTenant, errorMessage, handleTenantChange, reloadTenants, status, tenantId, tenants],
  )

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>
}
