import { useMemo } from 'react'
import { createControlPlaneApi } from '../../lib/api/index.ts'
import { useAuth } from '../auth/useAuth.ts'
import { useTenant } from './useTenant.ts'

export function useTenantControlPlaneApi() {
  const { getAccessToken } = useAuth()
  const { tenantId } = useTenant()

  return useMemo(
    () =>
      createControlPlaneApi({
        getTenantId: () => tenantId ?? undefined,
        getAccessToken,
      }),
    [getAccessToken, tenantId],
  )
}
