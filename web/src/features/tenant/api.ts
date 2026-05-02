import type { ControlPlaneApi, Tenant } from '../../lib/api/index.ts'

export type TenantOption = {
  id: string
  name: string
  createdAt: string
  updatedAt: string
}

type TenantApi = Pick<ControlPlaneApi, 'tenants'>

function toTenantOption(tenant: Tenant): TenantOption {
  return {
    id: tenant.id,
    name: tenant.name,
    createdAt: tenant.created_at,
    updatedAt: tenant.updated_at,
  }
}

export async function fetchTenants(api: TenantApi, signal?: AbortSignal): Promise<TenantOption[]> {
  const payload = await api.tenants.list({ signal })

  if (!Array.isArray(payload)) {
    throw new Error('Unable to load tenants (unexpected response)')
  }

  return payload.map(toTenantOption)
}
