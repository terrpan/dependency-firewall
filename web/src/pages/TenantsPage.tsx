import { useRef, useState, type FormEvent } from 'react'
import { Building2, Plus } from 'lucide-react'
import { Link } from 'react-router-dom'
import { ModalWizard, ModalWizardActions, type ModalWizardStep } from '../components/modal/index.ts'
import { useSessionControlPlaneApi } from '../features/auth/useSessionControlPlaneApi.ts'
import { useNotifications } from '../features/notifications/useNotifications.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { AsyncState, Badge, Button, EmptyState, Field, Input, PageHeader, ResourceList } from '../ui/index.ts'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'
import styles from './TenantsPage.module.css'

const dateFormatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })
const createTenantSteps = [
  { id: 'details', label: 'Details', description: 'Name the workspace.' },
  { id: 'review', label: 'Review', description: 'Confirm the new tenant.' },
] satisfies readonly ModalWizardStep[]

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? 'Unknown' : dateFormatter.format(date)
}

export function TenantsPage() {
  const api = useSessionControlPlaneApi()
  const { activeTenant, errorMessage, reloadTenants, setTenantId, status, tenants } = useTenant()
  const { notifyError, notifySuccess } = useNotifications()
  const [name, setName] = useState('')
  const [isCreating, setIsCreating] = useState(false)
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [createStep, setCreateStep] = useState(0)
  const nameInputRef = useRef<HTMLInputElement>(null)

  function openCreateWizard() {
    setName('')
    setCreateStep(0)
    setIsCreateOpen(true)
  }

  function closeCreateWizard() {
    if (isCreating) return
    setName('')
    setCreateStep(0)
    setIsCreateOpen(false)
  }

  async function createTenant(event: FormEvent) {
    event.preventDefault()
    const trimmedName = name.trim()
    if (!trimmedName) return

    if (createStep === 0) {
      setCreateStep(1)
      return
    }

    setIsCreating(true)
    try {
      const tenant = await api.tenants.create({ name: trimmedName })
      await reloadTenants()
      setTenantId(tenant.id)
      setName('')
      setCreateStep(0)
      setIsCreateOpen(false)
      notifySuccess('Tenant created', `${tenant.name} is now the active workspace.`)
    } catch (error) {
      notifyError('Unable to create tenant', error instanceof Error ? error.message : 'Try again.')
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <section className={applicationClass('page')}>
      <PageHeader
        eyebrow="Workspace scope"
        title="Tenants"
        summary="Choose which tenant to operate in. Upstreams, policies, decisions, and dependency graphs stay inside that workspace."
        actions={(
          <>
            <Badge tone={status === 'error' ? 'danger' : 'neutral'}>
              {status === 'loading'
                ? 'Loading tenants'
                : status === 'error'
                  ? 'Unavailable'
                  : `${tenants.length} tenant${tenants.length === 1 ? '' : 's'}`}
            </Badge>
            {status === 'ready' || status === 'empty' ? (
              <Button onClick={openCreateWizard} variant="primary">
                <Plus size={16} aria-hidden="true" />
                New tenant
              </Button>
            ) : null}
          </>
        )}
      />

      <div className={styles.layout}>
        <section className={styles.inventory} aria-labelledby="tenant-workspaces-heading">
          <div className={styles.inventoryHeader}>
            <div>
              <h3 id="tenant-workspaces-heading">Tenant workspaces</h3>
              <p>Switching tenants changes the scope of every tenant-owned page.</p>
            </div>
          </div>

          {status === 'loading' ? <AsyncState status="loading" /> : null}
          {status === 'error' ? (
            <AsyncState
              status="error"
              error={errorMessage ?? undefined}
              onRetry={() => void reloadTenants()}
            />
          ) : null}
          {status === 'empty' ? (
            <EmptyState
              title="No tenants yet"
              message="Create the first tenant to establish an isolated workspace for registries, policies, and decisions."
            />
          ) : null}

          {tenants.length > 0 ? (
            <ResourceList aria-label="Tenant workspaces" className={styles.list}>
              {tenants.map((tenant) => {
                const isActive = activeTenant?.id === tenant.id

                return (
                  <li className={styles.item} data-active={isActive || undefined} key={tenant.id}>
                    <div className={styles.itemMain}>
                      <div className={styles.tenantMark} aria-hidden="true">
                        <Building2 size={18} />
                      </div>
                      <div className={styles.identity}>
                        <h4>{tenant.name}</h4>
                        <div className={styles.metadata}>
                          <span>Updated {formatDate(tenant.updatedAt)}</span>
                          <span className={styles.tenantId}>ID {tenant.id}</span>
                        </div>
                      </div>
                    </div>

                    <div className={styles.itemActions}>
                      {isActive ? (
                        <>
                          <Badge tone="success">Active workspace</Badge>
                          <Link className={styles.routeLink} to="/">Open dashboard</Link>
                        </>
                      ) : (
                        <Button
                          aria-label={`Switch to ${tenant.name}`}
                          onClick={() => setTenantId(tenant.id)}
                        >
                          Switch tenant
                        </Button>
                      )}
                    </div>
                  </li>
                )
              })}
            </ResourceList>
          ) : null}
        </section>

      </div>

      <ModalWizard
        currentStep={createStep}
        description="Create an isolated workspace for one team, business unit, or environment."
        dismissible={!isCreating}
        footer={(
          <ModalWizardActions leading={<Button disabled={isCreating} onClick={closeCreateWizard}>Cancel</Button>}>
            {createStep > 0 ? <Button disabled={isCreating} onClick={() => setCreateStep(0)}>Back</Button> : null}
            <Button variant="primary" disabled={isCreating || !name.trim()} form="create-tenant-form" type="submit">
              {createStep === 0 ? 'Review details' : isCreating ? 'Creating…' : 'Create tenant'}
            </Button>
          </ModalWizardActions>
        )}
        initialFocusRef={nameInputRef}
        onClose={closeCreateWizard}
        open={isCreateOpen}
        showStepDescriptions={false}
        size="regular"
        stepGuideVariant="compact"
        steps={createTenantSteps}
        title="Create tenant"
      >
        <form aria-label="Create tenant" className={styles.form} id="create-tenant-form" onSubmit={createTenant}>
          {createStep === 0 ? (
            <div className={styles.wizardSection}>
              <div className={styles.formHeader}>
                <span className={styles.formIcon} aria-hidden="true"><Building2 size={20} /></span>
                <div>
                  <h3>Name the workspace</h3>
                  <p>Use the name operators already use for this team or environment.</p>
                </div>
              </div>

              <Field label="Tenant name">
                <Input
                  autoComplete="organization"
                  maxLength={120}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="Platform Engineering"
                  ref={nameInputRef}
                  required
                  value={name}
                />
              </Field>
            </div>
          ) : (
            <div className={styles.wizardSection}>
              <div className={styles.formHeader}>
                <span className={styles.formIcon} aria-hidden="true"><Building2 size={20} /></span>
                <div>
                  <h3>Review workspace</h3>
                  <p>The new tenant becomes active immediately after creation.</p>
                </div>
              </div>
              <dl className={styles.reviewCard}>
                <div><dt>Workspace name</dt><dd>{name.trim()}</dd></div>
                <div><dt>Scope</dt><dd>Isolated tenant</dd></div>
              </dl>
            </div>
          )}
        </form>
      </ModalWizard>
    </section>
  )
}
