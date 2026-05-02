import { createBrowserRouter } from 'react-router-dom'
import { AppShell } from '../components/AppShell.tsx'
import { RouteGuard } from '../features/auth/RouteGuard.tsx'
import { DashboardPage } from '../pages/DashboardPage.tsx'
import { EvaluationsPage } from '../pages/EvaluationsPage.tsx'
import { NotFoundPage } from '../pages/NotFoundPage.tsx'
import { PoliciesPage } from '../pages/PoliciesPage.tsx'
import { TenantsPage } from '../pages/TenantsPage.tsx'
import { UpstreamsPage } from '../pages/UpstreamsPage.tsx'

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
        element: <DashboardPage />,
      },
      {
        path: 'tenants',
        element: <TenantsPage />,
      },
      {
        path: 'upstreams',
        element: <UpstreamsPage />,
      },
      {
        path: 'policies',
        element: <PoliciesPage />,
      },
      {
        path: 'evaluations',
        element: <EvaluationsPage />,
      },
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
])
