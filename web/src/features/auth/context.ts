import { createContext } from 'react'

export type AuthUser = {
  id: string
  displayName: string
}

export type AuthSession = {
  accessToken?: string | null
  headers?: Record<string, string>
  roles: readonly string[]
  user?: AuthUser | null
}

export type AuthStatus = 'loading' | 'anonymous' | 'authenticated'

export type AuthContextValue = {
  status: AuthStatus
  session: AuthSession | null
  isAuthenticated: boolean
  getSessionHeaders: () => HeadersInit | undefined
  hasRole: (role: string) => boolean
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)
