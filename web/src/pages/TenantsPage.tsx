import { PlaceholderPage } from '../components/PlaceholderPage.tsx'

export function TenantsPage() {
  return (
    <PlaceholderPage
      title="Tenants"
      description="Management surface for tenant discovery, creation, and future membership flows."
      nextSteps={[
        'Reuse the shared tenant query for a tenant index view.',
        'Add tenant creation and selection flows.',
        'Surface tenant metadata beyond the shell switcher.',
      ]}
    />
  )
}
