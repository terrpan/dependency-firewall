import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useTenant } from '../features/tenant/useTenant.ts'
import { docsUrl } from '../lib/config.ts'

type NavigationItem = {
  to: string
  label: string
  summary: string
  end?: boolean
  requiresTenant?: boolean
}

const navigationItems = [
  { to: '/', label: 'Dashboard', summary: 'Recent activity and service status.', end: true, requiresTenant: true },
  { to: '/tenants', label: 'Tenants', summary: 'Tenant discovery and setup.' },
  { to: '/upstreams', label: 'Upstreams', summary: 'Registry endpoints and connection details.', requiresTenant: true },
  { to: '/policies', label: 'Policies', summary: 'Rules, versions, and rollback history.', requiresTenant: true },
  { to: '/evaluations', label: 'Evaluations', summary: 'Audit history and decision details.', requiresTenant: true },
] satisfies readonly NavigationItem[]

function getCurrentSection(pathname: string): Pick<NavigationItem, 'label' | 'summary'> {
  const currentItem = navigationItems.find((item) =>
    item.end ? pathname === item.to : pathname === item.to || pathname.startsWith(`${item.to}/`),
  )

  if (currentItem) {
    return currentItem
  }

  return {
    label: 'Workspace',
    summary: 'Move between control-plane views without losing your place.',
  }
}

function TenantShellState() {
  const { errorMessage, reloadTenants, status } = useTenant()

  if (status === 'loading') {
    return (
      <section className="page">
        <header className="page-header">
          <div>
            <h2>Loading tenants</h2>
            <p className="page-summary">Loading the tenant workspace.</p>
          </div>
          <span className="status-pill">Loading</span>
        </header>
      </section>
    )
  }

  if (status === 'error') {
    return (
      <section className="page">
        <header className="page-header">
          <div>
            <h2>Unable to load tenants</h2>
            <p className="page-summary">{errorMessage ?? 'The tenant list is unavailable right now.'}</p>
          </div>
          <button className="primary-button" onClick={() => void reloadTenants()} type="button">
            Retry
          </button>
        </header>
      </section>
    )
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h2>No tenants yet</h2>
          <p className="page-summary">Create a tenant to start using tenant-scoped pages.</p>
        </div>
        <span className="status-pill status-pill-neutral">Empty</span>
      </header>
    </section>
  )
}

export function AppShell() {
  const location = useLocation()
  const { activeTenant, hasTenants, isError, isLoading, setTenantId, status, tenantId, tenants } =
    useTenant()
  const currentSection = getCurrentSection(location.pathname)

  const tenantHelperText =
    status === 'loading'
      ? 'Loading available tenants.'
      : status === 'error'
        ? 'Tenant selection returns when the workspace is available again.'
      : status === 'empty'
        ? 'Create a tenant to unlock scoped pages.'
        : 'This tenant scopes the current workspace.'

  const shellStatusLabel =
    status === 'loading'
      ? 'Loading'
      : status === 'error'
        ? 'Issue'
        : status === 'empty'
          ? 'Empty'
          : 'Ready'

  const shellStatusClassName =
    status === 'ready'
      ? 'status-pill status-pill-success'
      : status === 'error'
        ? 'status-pill status-pill-danger'
        : 'status-pill status-pill-neutral'

  const tenantDisplayName = activeTenant?.name ?? (status === 'empty' ? 'Create a tenant' : 'Select a tenant')
  const tenantDisplayMeta = activeTenant?.id
    ? activeTenant.id
    : status === 'loading'
      ? 'Tenant list pending.'
      : status === 'error'
        ? 'Waiting for tenant data.'
        : status === 'empty'
          ? 'No tenant has been created yet.'
          : 'Choose a tenant to continue.'

  return (
    <div className="app-shell">
      <div className="shell-frame">
        <aside className="side-nav" aria-label="Primary">
          <div className="side-nav-top">
            <div className="brand-block">
              <p className="eyebrow">Dependency Firewall</p>
              <h1>Control plane</h1>
            </div>

            <label className="tenant-switcher" htmlFor="tenant-select">
              <div className="tenant-switcher-header">
                <span className="tenant-switcher-label">Tenant</span>
                <span className={shellStatusClassName}>{shellStatusLabel}</span>
              </div>
              <select
                id="tenant-select"
                disabled={isLoading || isError || !hasTenants}
                value={tenantId ?? ''}
                onChange={(event) => setTenantId(event.target.value)}
              >
                {!hasTenants ? (
                  <option value="">
                    {isLoading ? 'Loading tenants…' : isError ? 'Unable to load tenants' : 'No tenants'}
                  </option>
                ) : null}
                {tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>
                    {tenant.name} ({tenant.id})
                  </option>
                ))}
              </select>

              <div className="tenant-active">
                <div className="stack-sm">
                  <strong>{tenantDisplayName}</strong>
                  <span className="tenant-meta">{tenantDisplayMeta}</span>
                </div>
                <small>{tenantHelperText}</small>
              </div>
            </label>
          </div>

          <nav className="nav-section">
            <p className="nav-section-label">Navigation</p>
            <ul>
              {navigationItems.map((item) => (
                <li key={item.to}>
                  {item.requiresTenant && status !== 'ready' ? (
                    <span className="nav-link disabled">{item.label}</span>
                  ) : (
                    <NavLink
                      className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                      end={item.end}
                      to={item.to}
                    >
                      {item.label}
                    </NavLink>
                  )}
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        <div className="shell-main">
          <header className="shell-topbar">
            <div className="shell-current">
              <p className="eyebrow">Current work</p>
              <h2 className="shell-title">{currentSection.label}</h2>
              <p className="shell-subtitle">{currentSection.summary}</p>
            </div>

            <div className="shell-actions">
              <a className="shell-action-link" href={docsUrl} target="_blank" rel="noreferrer">
                Docs
              </a>
            </div>
          </header>

          <main className="content">
            {status === 'ready' ? <Outlet /> : <div className="shell-state"><TenantShellState /></div>}
          </main>
        </div>
      </div>
    </div>
  )
}
