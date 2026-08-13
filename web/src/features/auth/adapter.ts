import type { ReactNode } from 'react'
import type { AuthSession, AuthStatus } from './context.ts'

export type AuthSnapshot = {
  status: AuthStatus
  session: AuthSession | null
  getAccessToken: () => Promise<string | null>
  signIn?: () => void | Promise<void>
  signOut?: () => void | Promise<void>
  accountControl?: ReactNode
}

export type AuthAdapter = { useSnapshot: () => AuthSnapshot }

declare global {
  interface Window {
    __DEPENDENCY_FIREWALL_TEST_AUTH__?: {
      state: 'anonymous' | 'authenticated' | 'unauthorized' | 'expired' | 'error'
      token?: string
    }
  }
}

export const localAuthAdapter: AuthAdapter = {
	useSnapshot() {
    const testAuth = typeof window === 'undefined' ? undefined : window.__DEPENDENCY_FIREWALL_TEST_AUTH__
    if (testAuth?.state === 'authenticated') {
      return {
        status: 'authenticated',
        session: { roles: ['operator'], user: { id: 'e2e-operator', displayName: 'E2E Operator' } },
        getAccessToken: async () => testAuth.token ?? 'e2e-token',
      }
    }
    if (testAuth?.state === 'unauthorized')
      return { status: 'unauthorized', session: null, getAccessToken: async () => null }
    if (testAuth?.state === 'expired' || testAuth?.state === 'error')
      return { status: 'error', session: null, getAccessToken: async () => null }
    return { status: 'anonymous', session: null, getAccessToken: async () => null }
  },
}
