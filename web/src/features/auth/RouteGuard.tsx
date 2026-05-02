import { type PropsWithChildren, type ReactNode } from 'react'
import { useRouteGuard, type RouteGuardOptions } from './useRouteGuard.ts'

export type RouteGuardProps = PropsWithChildren<
  RouteGuardOptions & {
    fallback?: ReactNode
  }
>

export function RouteGuard({ children, fallback = null, ...options }: RouteGuardProps) {
  const guard = useRouteGuard(options)

  if (!guard.isAllowed) {
    return <>{fallback}</>
  }

  return <>{children}</>
}
