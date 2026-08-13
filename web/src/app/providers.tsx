import { ClerkProvider } from '@clerk/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useState, type PropsWithChildren } from 'react'
import { AuthProvider } from '../features/auth/AuthProvider.tsx'
import type { AuthAdapter } from '../features/auth/adapter.ts'
import { clerkAuthAdapter } from '../features/auth/clerkAdapter.tsx'
import { NotificationsProvider } from '../features/notifications/NotificationsProvider.tsx'
import { TenantProvider } from '../features/tenant/TenantContext.tsx'
import { clerkPublishableKey } from '../lib/config.ts'

type AppProvidersProps = PropsWithChildren<{ authAdapter?: AuthAdapter }>

function ProviderTree({ children, authAdapter }: AppProvidersProps) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            refetchOnWindowFocus: false,
            retry: 1,
            staleTime: 30_000,
          },
        },
      }),
  )

  return (
    <QueryClientProvider client={queryClient}>
      <NotificationsProvider>
        <AuthProvider adapter={authAdapter}>
          <TenantProvider>{children}</TenantProvider>
        </AuthProvider>
      </NotificationsProvider>
    </QueryClientProvider>
  )
}

export function AppProviders({ children, authAdapter }: AppProvidersProps) {
  if (authAdapter || !clerkPublishableKey) {
    return <ProviderTree authAdapter={authAdapter}>{children}</ProviderTree>
  }

  return (
    <ClerkProvider publishableKey={clerkPublishableKey}>
      <ProviderTree authAdapter={clerkAuthAdapter}>{children}</ProviderTree>
    </ClerkProvider>
  )
}
