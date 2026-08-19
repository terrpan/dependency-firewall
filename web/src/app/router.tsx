import { lazy } from 'react'
import { createBrowserRouter } from 'react-router-dom'
import { AppShell } from '../components/AppShell.tsx'
import { RouteGuard } from '../features/auth/RouteGuard.tsx'
import { RouteElement } from './RouteSuspense.tsx'

const DashboardPage = lazy(() =>
  import('../pages/DashboardPage.tsx').then(({ DashboardPage }) => ({ default: DashboardPage })),
)
const EvaluationsPage = lazy(() =>
  import('../pages/EvaluationsPage.tsx').then(({ EvaluationsPage }) => ({ default: EvaluationsPage })),
)
const DependencyGraphsPage = lazy(() =>
  import('../pages/DependencyGraphsPage.tsx').then(({ DependencyGraphsPage }) => ({ default: DependencyGraphsPage })),
)
const NotFoundPage = lazy(() =>
  import('../pages/NotFoundPage.tsx').then(({ NotFoundPage }) => ({ default: NotFoundPage })),
)
const PoliciesPage = lazy(() =>
  import('../pages/PoliciesPage.tsx').then(({ PoliciesPage }) => ({ default: PoliciesPage })),
)
const TenantsPage = lazy(() => import('../pages/TenantsPage.tsx').then(({ TenantsPage }) => ({ default: TenantsPage })))
const UpstreamsPage = lazy(() =>
  import('../pages/UpstreamsPage.tsx').then(({ UpstreamsPage }) => ({ default: UpstreamsPage })),
)

export const router = createBrowserRouter([
  {
    path: '/',
    element: (
      <RouteGuard requireSession>
        <AppShell />
      </RouteGuard>
    ),
    children: [
      {
        index: true,
        element: <RouteElement Page={DashboardPage} />,
      },
      {
        path: 'tenants',
        element: <RouteElement Page={TenantsPage} />,
      },
      {
        path: 'upstreams',
        element: <RouteElement Page={UpstreamsPage} />,
      },
      {
        path: 'policies',
        element: <RouteElement Page={PoliciesPage} />,
      },
      {
        path: 'evaluations',
        element: <RouteElement Page={EvaluationsPage} />,
      },
      {
        path: 'dependency-graphs',
        element: <RouteElement Page={DependencyGraphsPage} />,
      },
      {
        path: '*',
        element: <RouteElement Page={NotFoundPage} />,
      },
    ],
  },
])
