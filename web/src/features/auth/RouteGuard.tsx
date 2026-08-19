import { type PropsWithChildren, type ReactNode } from 'react'
import { Button, Panel } from '../../ui/index.ts'
import { useAuth } from './useAuth.ts'
import { useRouteGuard, type RouteGuardOptions } from './useRouteGuard.ts'
import styles from './AuthState.module.css'

export type RouteGuardProps = PropsWithChildren<
  RouteGuardOptions & {
    fallback?: ReactNode
  }
>

export function RouteGuard({ children, fallback = null, ...options }: RouteGuardProps) {
  const auth = useAuth()
  const guard = useRouteGuard(options)

  if (options.requireSession && auth.status === 'loading') {
    return (
      <AuthState title="Checking your session" message="Confirming access to the Dependency Firewall control plane." />
    )
  }

  if (options.requireSession && auth.status === 'unauthorized') {
    return (
      <AuthState
        title="Access denied"
        message="Your account does not have permission to open this control plane."
        action={auth.signOut ? <Button onClick={() => void auth.signOut?.()}>Sign out</Button> : undefined}
      />
    )
  }

  if (options.requireSession && auth.status === 'error') {
    return (
      <AuthState
        title="Session expired"
        message="Your session could not be verified. Sign in again to continue."
        action={
          auth.signIn ? (
            <Button variant="primary" onClick={() => void auth.signIn?.()}>
              Sign in again
            </Button>
          ) : undefined
        }
      />
    )
  }

  if (options.requireSession && auth.status === 'anonymous' && auth.signIn) {
    return (
      <AuthState
        title="Sign in required"
        message="Authenticate to open the Dependency Firewall control plane."
        action={
          <Button variant="primary" onClick={() => void auth.signIn?.()}>
            Sign in
          </Button>
        }
      />
    )
  }

  if (!guard.isAllowed) {
    return <>{fallback}</>
  }

  return <>{children}</>
}

function AuthState({ title, message, action }: { title: string; message: string; action?: ReactNode }) {
  return (
    <main className={styles.screen}>
      <Panel className={styles.card} padding="lg">
        <span className={styles.mark} aria-hidden="true">
          DF
        </span>
        <h1>{title}</h1>
        <p>{message}</p>
        {action}
      </Panel>
    </main>
  )
}
