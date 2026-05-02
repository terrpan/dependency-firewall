import { useMemo } from 'react'
import { createControlPlaneApi } from '../../lib/api/index.ts'
import { useAuth } from '../auth/useAuth.ts'
import { useTenant } from './useTenant.ts'

export function useTenantControlPlaneApi() {
  const { getSessionHeaders } = useAuth()
  const { tenantId } = useTenant()

  return useMemo(
    () =>
      createControlPlaneApi({
        getTenantId: () => tenantId ?? undefined,
        getSessionHeaders,
      }),
    [getSessionHeaders, tenantId],
  )
}
