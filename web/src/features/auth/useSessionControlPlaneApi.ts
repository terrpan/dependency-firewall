import { useMemo } from 'react'
import { createControlPlaneApi } from '../../lib/api/index.ts'
import { useAuth } from './useAuth.ts'

export function useSessionControlPlaneApi() {
  const { getAccessToken } = useAuth()

  return useMemo(
    () =>
      createControlPlaneApi({
        getAccessToken,
      }),
    [getAccessToken],
  )
}
