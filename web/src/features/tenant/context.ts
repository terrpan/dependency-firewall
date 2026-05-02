import { createContext } from 'react'
import type { TenantOption } from './api.ts'

export type TenantStatus = 'loading' | 'ready' | 'empty' | 'error'

export type TenantContextValue = {
  tenantId: string | null
  setTenantId: (tenantId: string) => void
  tenants: readonly TenantOption[]
  activeTenant: TenantOption | null
  reloadTenants: () => Promise<void>
  status: TenantStatus
  hasTenants: boolean
  isLoading: boolean
  isError: boolean
  errorMessage: string | null
}

export const tenantStorageKey = 'dependency-firewall.tenant-id'

export const TenantContext = createContext<TenantContextValue | undefined>(undefined)
