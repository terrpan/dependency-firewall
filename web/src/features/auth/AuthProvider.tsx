import { useCallback, useMemo, type PropsWithChildren } from 'react'
import { AuthContext, type AuthContextValue, type AuthSession } from './context.ts'
import { buildSessionHeaders } from './session.ts'

const anonymousSession: AuthSession | null = null

export function AuthProvider({ children }: PropsWithChildren) {
  const session = anonymousSession

  const getSessionHeaders = useCallback(() => buildSessionHeaders(session), [session])
  const hasRole = useCallback((role: string) => Boolean(session?.roles.includes(role)), [session])

  const value = useMemo<AuthContextValue>(
    () => ({
      status: session ? 'authenticated' : 'anonymous',
      session,
      isAuthenticated: Boolean(session),
      getSessionHeaders,
      hasRole,
    }),
    [getSessionHeaders, hasRole, session],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
