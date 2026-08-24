import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ModalDialog } from '../../components/modal/index.ts'
import { useSessionControlPlaneApi } from '../auth/useSessionControlPlaneApi.ts'
import { Badge, Button, EmptyState, Panel, ResourceList } from '../../ui/index.ts'
import { ProxySetup } from './ProxySetup.tsx'
import styles from './ProxyInstallationsPanel.module.css'

export function ProxyInstallationsPanel({ tenantId, tenantName }: { tenantId: string; tenantName: string }) {
  const api = useSessionControlPlaneApi()
  const [setupOpen, setSetupOpen] = useState(false)
  const query = useQuery({
    queryKey: ['proxy-installations', tenantId],
    queryFn: () => api.proxyInstallations.list(tenantId),
    refetchInterval: 5000,
  })

  async function rename(id: string, currentName: string) {
    const name = window.prompt('Proxy installation name', currentName)?.trim()
    if (!name || name === currentName) return
    await api.proxyInstallations.rename(tenantId, id, { name })
    await query.refetch()
  }

  async function revoke(id: string, name: string) {
    if (!window.confirm(`Revoke ${name}? It will immediately lose Tenant access.`)) return
    await api.proxyInstallations.revoke(tenantId, id)
    await query.refetch()
  }

  const installations = query.data ?? []
  return (
    <Panel className={styles.panel}>
      <div className={styles.header}>
        <div>
          <h3>Proxy installations</h3>
          <p>Self-hosted proxies authorized for this Tenant.</p>
        </div>
        <Button onClick={() => setSetupOpen(true)} variant="primary">
          Add proxy
        </Button>
      </div>
      {query.isError ? <p role="alert">Unable to load proxy installations.</p> : null}
      {!query.isPending && installations.length === 0 ? (
        <EmptyState title="No proxies connected" message="Add a self-hosted proxy to enforce this Tenant’s policies." />
      ) : null}
      {installations.length > 0 ? (
        <ResourceList aria-label="Proxy installations">
          {installations.map((installation) => (
            <li className={styles.item} key={installation.id}>
              <div>
                <strong>{installation.name}</strong>
                <span>
                  {installation.first_connected_at
                    ? `Connected ${new Date(installation.first_connected_at).toLocaleString()}`
                    : 'Waiting for first connection'}
                </span>
              </div>
              <div className={styles.actions}>
                <Badge
                  tone={
                    installation.status === 'active'
                      ? 'success'
                      : installation.status === 'revoked'
                        ? 'danger'
                        : 'warning'
                  }
                >
                  {installation.status}
                </Badge>
                {installation.status !== 'revoked' ? (
                  <Button onClick={() => void rename(installation.id, installation.name)}>Rename</Button>
                ) : null}
                {installation.status !== 'revoked' ? (
                  <Button onClick={() => void revoke(installation.id, installation.name)} variant="danger">
                    Revoke
                  </Button>
                ) : null}
              </div>
            </li>
          ))}
        </ResourceList>
      ) : null}
      <ModalDialog
        footer={
          <>
            <Button onClick={() => setSetupOpen(false)}>Close</Button>
            <Link className={styles.activateLink} to="/activate">
              Enter activation code
            </Link>
          </>
        }
        onClose={() => setSetupOpen(false)}
        open={setupOpen}
        size="wide"
        title="Add proxy"
      >
        <ProxySetup tenantName={tenantName} />
      </ModalDialog>
    </Panel>
  )
}
