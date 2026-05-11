import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigationType } from 'react-router-dom'
import { useAuth } from '../features/auth/useAuth.ts'
import { useTenant } from '../features/tenant/useTenant.ts'
import { docsUrl } from '../lib/config.ts'
import { recordSpanError, startSpan } from '../lib/telemetry.ts'

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

const themeStorageKey = 'dependency-firewall-theme'

type ThemeMode = 'system' | 'dark' | 'light'

function getInitialTheme(): ThemeMode {
  if (typeof window === 'undefined') {
    return 'system'
  }

  const storedTheme = window.localStorage.getItem(themeStorageKey)
  if (storedTheme === 'system' || storedTheme === 'dark' || storedTheme === 'light') {
    return storedTheme
  }

  return 'system'
}

function resolveTheme(theme: ThemeMode): 'dark' | 'light' {
  if (theme !== 'system') {
    return theme
  }

  if (typeof window === 'undefined') {
    return 'dark'
  }

  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function getNextTheme(theme: ThemeMode): ThemeMode {
  if (theme === 'system') {
    return 'light'
  }

  if (theme === 'light') {
    return 'dark'
  }

  return 'system'
}

function ThemeIcon({ theme }: { theme: ThemeMode }) {
  if (theme === 'light') {
    return (
      <svg aria-hidden="true" className="theme-icon" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2.5M12 19.5V22M4.93 4.93 6.7 6.7M17.3 17.3l1.77 1.77M2 12h2.5M19.5 12H22M4.93 19.07 6.7 17.3M17.3 6.7l1.77-1.77" />
      </svg>
    )
  }

  if (theme === 'dark') {
    return (
      <svg aria-hidden="true" className="theme-icon" viewBox="0 0 24 24">
        <path d="M20.2 14.9A7.7 7.7 0 0 1 9.1 3.8 8.8 8.8 0 1 0 20.2 14.9Z" />
      </svg>
    )
  }

  return (
    <svg aria-hidden="true" className="theme-icon" viewBox="0 0 24 24">
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </svg>
  )
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
          <button className="secondary-button" onClick={() => void reloadTenants()} type="button">
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
  const navigationType = useNavigationType()
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme)
  const { session, status: authStatus } = useAuth()
  const { activeTenant, hasTenants, isError, isLoading, setTenantId, status, tenantId, tenants } =
    useTenant()

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

  useEffect(() => {
    window.localStorage.setItem(themeStorageKey, theme)
    document.documentElement.dataset.theme = resolveTheme(theme)

    if (theme !== 'system') {
      return
    }

    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)')
    const handleSystemThemeChange = () => {
      document.documentElement.dataset.theme = resolveTheme('system')
    }

    mediaQuery.addEventListener('change', handleSystemThemeChange)

    return () => {
      mediaQuery.removeEventListener('change', handleSystemThemeChange)
    }
  }, [theme])

  useEffect(() => {
    const span = startSpan('ui.navigation', {
      'navigation.type': navigationType,
      'route.path': location.pathname,
      'route.search': location.search,
      'tenant.id': tenantId ?? 'none',
    })

    const frameId = window.requestAnimationFrame(() => {
      try {
        span.setAttribute('document.title', document.title)
      } catch (error) {
        recordSpanError(span, error, 'navigation tracing failed')
      } finally {
        span.end()
      }
    })

    return () => {
      window.cancelAnimationFrame(frameId)
    }
  }, [location.pathname, location.search, navigationType, tenantId])

  const nextTheme = getNextTheme(theme)
  const themeLabel =
    theme === 'system'
      ? 'Theme: System'
      : theme === 'light'
        ? 'Theme: Light'
        : 'Theme: Dark'
  const accountName = session?.user?.displayName?.trim() || 'Local session'
  const accountMeta =
    authStatus === 'authenticated'
      ? session?.roles.length
        ? session.roles.join(', ')
        : session?.user?.id ?? 'Authenticated'
      : 'Authentication not configured'

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

          <div className="shell-utility-actions side-docs-link">
            <a className="shell-action-link" href={docsUrl} target="_blank" rel="noreferrer">
              Docs
            </a>
          </div>
        </aside>

        <div className="shell-main">
          <header className="shell-utility-bar">
            <div className="account-summary">
              <span className="account-avatar" aria-hidden="true">
                {accountName.slice(0, 1).toUpperCase()}
              </span>
              <div className="stack-sm">
                <strong>{accountName}</strong>
                <span>{accountMeta}</span>
              </div>
            </div>

            <div className="shell-utility-actions">
              <button
                aria-label={`${themeLabel}. Switch to ${nextTheme} theme`}
                className="shell-icon-button shell-theme-toggle"
                onClick={() => setTheme(nextTheme)}
                type="button"
                title={`Switch to ${nextTheme} theme`}
              >
                <ThemeIcon theme={theme} />
              </button>
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
