import { useEffect, useState, type FormEvent } from 'react'
import { CheckCircle2, KeyRound } from 'lucide-react'
import { useSessionControlPlaneApi } from '../features/auth/useSessionControlPlaneApi.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import type { ProxyEnrollment } from '../lib/api/index.ts'
import { ApiError } from '../lib/api/index.ts'
import { AsyncState, Badge, Button, Field, Input, PageHeader, Panel } from '../ui/index.ts'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'
import styles from './ActivatePage.module.css'

type ActivationState = 'entry' | 'resolving' | 'confirm' | 'approving' | 'waiting' | 'success' | 'error'

export function ActivatePage() {
  const api = useSessionControlPlaneApi()
  const { activeTenant, tenants, setTenantId } = useTenant()
  const [code, setCode] = useState('')
  const [installationName, setInstallationName] = useState('Self-hosted proxy')
  const [enrollment, setEnrollment] = useState<ProxyEnrollment | null>(null)
  const [installationId, setInstallationId] = useState<string | null>(null)
  const [state, setState] = useState<ActivationState>('entry')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (state !== 'waiting' || !activeTenant || !installationId) return
    let cancelled = false
    const poll = async () => {
      try {
        const installation = await api.proxyInstallations.get(activeTenant.id, installationId)
        if (cancelled) return
        if (installation.status === 'revoked') {
          setMessage('This proxy installation was revoked.')
          setState('error')
        } else if (installation.status === 'active' && installation.first_connected_at) {
          setState('success')
        } else {
          window.setTimeout(() => void poll(), 3000)
        }
      } catch (error) {
        if (!cancelled) {
          setMessage(error instanceof Error ? error.message : 'Unable to check connection state.')
          setState('error')
        }
      }
    }
    void poll()
    return () => {
      cancelled = true
    }
  }, [activeTenant, api, installationId, state])

  async function resolveCode(event: FormEvent) {
    event.preventDefault()
    if (!code.trim()) return
    setState('resolving')
    try {
      const resolved = await api.proxyEnrollments.resolve({ user_code: code.trim() })
      setEnrollment(resolved)
      setInstallationName(resolved.proposed_name?.trim() || 'Self-hosted proxy')
      setState('confirm')
    } catch (error) {
      setMessage(activationErrorMessage(error))
      setState('error')
    }
  }

  async function approve(event: FormEvent) {
    event.preventDefault()
    if (!enrollment || !activeTenant || !installationName.trim()) return
    setState('approving')
    try {
      const approved = await api.proxyEnrollments.approve(enrollment.id, {
        user_code: code.trim(),
        tenant_id: activeTenant.id,
        installation_name: installationName.trim(),
      })
      if (approved.installation_id) {
        setInstallationId(approved.installation_id)
        setState('waiting')
        return
      }
      // Compatibility fallback for an older control plane response.
      const installations = await api.proxyInstallations.list(activeTenant.id)
      const pending = installations.find((item) => item.name === installationName.trim() && item.status === 'pending')
      if (!pending) throw new Error('Activation approved, but its installation could not be located.')
      setInstallationId(pending.id)
      setState('waiting')
    } catch (error) {
      setMessage(activationErrorMessage(error))
      setState('error')
    }
  }

  return (
    <section className={applicationClass('page')}>
      <PageHeader
        eyebrow="Proxy setup"
        title="Activate a proxy"
        summary="Confirm the code shown by your proxy and bind it to one Tenant."
      />
      <Panel className={styles.card}>
        {state === 'entry' || state === 'resolving' || state === 'error' ? (
          <form className={styles.form} onSubmit={resolveCode}>
            <KeyRound aria-hidden="true" />
            <div>
              <h3>Enter activation code</h3>
              <p>The code is eight characters and is shown only by the new proxy.</p>
            </div>
            <Field label="Activation code">
              <Input
                autoCapitalize="characters"
                onChange={(event) => setCode(event.target.value)}
                placeholder="ABCD-EFGH"
                value={code}
              />
            </Field>
            {state === 'error' ? <AsyncState status="error" error={message} /> : null}
            <Button disabled={state === 'resolving' || !code.trim()} type="submit" variant="primary">
              {state === 'resolving' ? 'Checking…' : 'Continue'}
            </Button>
          </form>
        ) : null}
        {state === 'confirm' || state === 'approving' ? (
          <form className={styles.form} onSubmit={approve}>
            <Badge tone="neutral">Code verified</Badge>
            <div>
              <h3>Confirm proxy</h3>
              <p>This grants the new proxy access only to the selected Tenant.</p>
            </div>
            <Field label="Tenant">
              <select onChange={(event) => setTenantId(event.target.value)} value={activeTenant?.id ?? ''}>
                {tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Installation name">
              <Input onChange={(event) => setInstallationName(event.target.value)} value={installationName} />
            </Field>
            <Button disabled={state === 'approving' || !activeTenant} type="submit" variant="primary">
              {state === 'approving' ? 'Approving…' : 'Approve proxy'}
            </Button>
          </form>
        ) : null}
        {state === 'waiting' ? (
          <div>
            <AsyncState status="loading" />
            <p>Approved. Waiting for the proxy to connect…</p>
          </div>
        ) : null}
        {state === 'success' ? (
          <div className={styles.success}>
            <CheckCircle2 aria-hidden="true" />
            <h3>Proxy connected</h3>
            <p>The installation is active for {activeTenant?.name}.</p>
          </div>
        ) : null}
      </Panel>
    </section>
  )
}

function activationErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Sign in to approve this proxy.'
    if (error.status === 403)
      return 'You are not authorized to activate a proxy for this Tenant, or the request was denied.'
    if (error.status === 410) return 'This code expired or was already used.'
    if (error.status === 400) return 'This activation code is invalid.'
  }
  return error instanceof Error ? error.message : 'Unable to activate this proxy.'
}
