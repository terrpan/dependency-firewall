import { useCallback, useMemo, type PropsWithChildren } from 'react'
import { AuthContext, type AuthContextValue } from './context.ts'
import { localAuthAdapter, type AuthAdapter } from './adapter.ts'

export function AuthProvider({ children, adapter = localAuthAdapter }: PropsWithChildren<{ adapter?: AuthAdapter }>) {
  const snapshot = adapter.useSnapshot()
  const session = snapshot.session

  const getAccessToken = useCallback(() => snapshot.getAccessToken(), [snapshot])
  const hasRole = useCallback((role: string) => Boolean(session?.roles.includes(role)), [session])

  const value = useMemo<AuthContextValue>(
    () => ({
      status: snapshot.status,
      session,
      isAuthenticated: Boolean(session),
      getAccessToken,
      hasRole,
      signIn: snapshot.signIn,
      signOut: snapshot.signOut,
      accountControl: snapshot.accountControl,
    }),
    [getAccessToken, hasRole, session, snapshot],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
