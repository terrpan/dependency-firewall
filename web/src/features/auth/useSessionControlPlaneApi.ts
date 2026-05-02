import { useMemo } from 'react'
import { createControlPlaneApi } from '../../lib/api/index.ts'
import { useAuth } from './useAuth.ts'

export function useSessionControlPlaneApi() {
  const { getSessionHeaders } = useAuth()

  return useMemo(
    () =>
      createControlPlaneApi({
        getSessionHeaders,
      }),
    [getSessionHeaders],
  )
}
