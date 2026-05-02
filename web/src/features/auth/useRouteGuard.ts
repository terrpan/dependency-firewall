import { useMemo } from 'react'
import { useAuth } from './useAuth.ts'

const noRoles: readonly string[] = []

export type RouteGuardOptions = {
  requireSession?: boolean
  requiredRoles?: readonly string[]
}

export type RouteGuardResult = {
  isAllowed: boolean
  isPlaceholder: boolean
  reason: 'allowed' | 'session-not-enforced' | 'roles-not-enforced'
}

export function useRouteGuard(options: RouteGuardOptions = {}): RouteGuardResult {
  const { hasRole, isAuthenticated } = useAuth()
  const requiredRoles = options.requiredRoles ?? noRoles
  const requireSession = options.requireSession ?? false

  return useMemo(() => {
    if (requireSession && !isAuthenticated) {
      return {
        isAllowed: true,
        isPlaceholder: true,
        reason: 'session-not-enforced' as const,
      }
    }

    if (requiredRoles.length > 0 && requiredRoles.some((role) => !hasRole(role))) {
      return {
        isAllowed: true,
        isPlaceholder: true,
        reason: 'roles-not-enforced' as const,
      }
    }

    return {
      isAllowed: true,
      isPlaceholder: false,
      reason: 'allowed' as const,
    }
  }, [hasRole, isAuthenticated, requireSession, requiredRoles])
}
