import { useState, type FormEvent } from 'react'
import { Building2, Plus } from 'lucide-react'
import { useSessionControlPlaneApi } from '../features/auth/useSessionControlPlaneApi.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { AsyncState, Badge, Button, EmptyState, Field, Input, PageHeader, Panel, ResourceList } from '../ui/index.ts'
import styles from './TenantsPage.module.css'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'

export function TenantsPage() {
  const api = useSessionControlPlaneApi()
  const { activeTenant, errorMessage, reloadTenants, setTenantId, status, tenants } = useTenant()
  const { notifyError, notifySuccess } = useNotifications()
  const [name, setName] = useState('')
  const [isCreating, setIsCreating] = useState(false)

  async function createTenant(event: FormEvent) {
    event.preventDefault()
    const trimmedName = name.trim()
    if (!trimmedName) return
    setIsCreating(true)
    try {
      const tenant = await api.tenants.create({ name: trimmedName })
      await reloadTenants()
      setTenantId(tenant.id)
      setName('')
      notifySuccess('Tenant created', `${tenant.name} is ready for configuration.`)
    } catch (error) {
      notifyError('Unable to create tenant', error instanceof Error ? error.message : 'Try again.')
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <section className={applicationClass("page")}>
      <PageHeader eyebrow="Administration" title="Tenants" summary="Choose the workspace that owns its registries, policies, and audit history." actions={<Badge tone={status === 'error' ? 'danger' : status === 'ready' ? 'success' : 'neutral'}>{tenants.length} tenant{tenants.length === 1 ? '' : 's'}</Badge>} />
      <div className={styles.layout}>
        <div>
          {status === 'loading' ? <AsyncState status="loading" /> : null}
          {status === 'error' ? <AsyncState status="error" error={errorMessage ?? undefined} onRetry={() => void reloadTenants()} /> : null}
          {status === 'empty' ? <EmptyState title="No tenants yet" message="Create the first tenant to unlock registries, policies, and evaluations." /> : null}
          {tenants.length ? <ResourceList aria-label="Tenants">{tenants.map(tenant => <li className={styles.item} key={tenant.id}><div><h3>{tenant.name}</h3><p>{tenant.id}</p><span className={styles.date}>Updated {new Date(tenant.updatedAt).toLocaleDateString()}</span></div><Button variant={activeTenant?.id === tenant.id ? 'primary' : 'default'} disabled={activeTenant?.id === tenant.id} onClick={() => setTenantId(tenant.id)}>{activeTenant?.id === tenant.id ? 'Active' : 'Open'}</Button></li>)}</ResourceList> : null}
        </div>
        <Panel padding="lg">
          <form className={styles.form} onSubmit={createTenant}>
            <Building2 size={22} aria-hidden="true" />
            <h3>Create tenant</h3>
            <p>Use a team or environment boundary. You can switch tenants at any time.</p>
            <Field label="Tenant name" hint="Choose a name operators will recognize in the navigation."><Input autoComplete="organization" maxLength={120} onChange={event => setName(event.target.value)} placeholder="Platform Engineering" required value={name} /></Field>
            <div className={styles.actions}><Button variant="primary" disabled={isCreating || !name.trim()} type="submit"><Plus size={16}/>{isCreating ? 'Creating…' : 'Create tenant'}</Button></div>
          </form>
        </Panel>
      </div>
    </section>
  )
}
