import { createContext, type ReactNode } from 'react'

export type AuthUser = {
  id: string
  displayName: string
}

export type AuthSession = {
  roles: readonly string[]
  user?: AuthUser | null
  organizationId?: string | null
}

export type AuthStatus = 'loading' | 'anonymous' | 'authenticated' | 'unauthorized' | 'error'

export type AuthContextValue = {
  status: AuthStatus
  session: AuthSession | null
  isAuthenticated: boolean
  getAccessToken: () => Promise<string | null>
  hasRole: (role: string) => boolean
  signIn?: () => void | Promise<void>
  signOut?: () => void | Promise<void>
  accountControl?: ReactNode
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)
