import { OrganizationSwitcher, useAuth as useClerkAuth, useClerk, useUser } from '@clerk/react'
import { useMemo } from 'react'
import type { AuthAdapter, AuthSnapshot } from './adapter.ts'

function canonicalRole(role: string | null | undefined) {
  return role?.startsWith('org:') ? role.slice(4) : role
}

function useClerkSnapshot(): AuthSnapshot {
  const { isLoaded, isSignedIn, orgId, orgRole, getToken } = useClerkAuth()
  const { user } = useUser()
  const clerk = useClerk()

  return useMemo(() => {
    if (!isLoaded) {
      return { status: 'loading', session: null, getAccessToken: async () => null }
    }
    if (!isSignedIn) {
      return {
        status: 'anonymous',
        session: null,
        getAccessToken: async () => null,
        signIn: () => clerk.openSignIn(),
      }
    }
    if (!orgId) {
      return {
        status: 'unauthorized',
        session: null,
        getAccessToken: async () => null,
        signOut: () => clerk.signOut(),
        accountControl: <OrganizationSwitcher hidePersonal />,
      }
    }

    const role = canonicalRole(orgRole)
    return {
      status: 'authenticated',
      session: {
        roles: role ? [role] : [],
        organizationId: orgId,
        user: user
          ? {
              id: user.id,
              displayName: user.fullName || user.primaryEmailAddress?.emailAddress || user.id,
            }
          : null,
      },
      getAccessToken: () => getToken(),
      signOut: () => clerk.signOut(),
      accountControl: <OrganizationSwitcher hidePersonal />,
    }
  }, [clerk, getToken, isLoaded, isSignedIn, orgId, orgRole, user])
}

export const clerkAuthAdapter: AuthAdapter = { useSnapshot: useClerkSnapshot }
