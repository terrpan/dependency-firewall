import type { HTMLAttributes, ReactNode } from 'react'
import { Button, Panel } from '../primitives/Primitives.tsx'
import styles from './Patterns.module.css'

export function PageHeader({
  eyebrow,
  title,
  summary,
  actions,
}: {
  eyebrow?: string
  title: string
  summary?: ReactNode
  actions?: ReactNode
}) {
  return (
    <header className={styles.header}>
      <div>
        {eyebrow ? <p className={styles.eyebrow}>{eyebrow}</p> : null}
        <h2>{title}</h2>
        {summary ? <p className={styles.summary}>{summary}</p> : null}
      </div>
      {actions ? <div className={styles.actions}>{actions}</div> : null}
    </header>
  )
}
export function ResourceList(props: HTMLAttributes<HTMLUListElement>) {
  return <ul {...props} className={[styles.list, props.className].filter(Boolean).join(' ')} />
}
export function EmptyState({ title, message, action }: { title: string; message: string; action?: ReactNode }) {
  return (
    <Panel>
      <div className={styles.state}>
        <h3>{title}</h3>
        <span>{message}</span>
        {action}
      </div>
    </Panel>
  )
}
export function AsyncState({
  status,
  error,
  onRetry,
}: {
  status: 'loading' | 'error'
  error?: string
  onRetry?: () => void
}) {
  return (
    <Panel aria-live="polite">
      <div className={styles.state}>
        <h3>{status === 'loading' ? 'Loading…' : 'Something went wrong'}</h3>
        {error ? <span>{error}</span> : null}
        {status === 'error' && onRetry ? <Button onClick={onRetry}>Retry</Button> : null}
      </div>
    </Panel>
  )
}
