import { Link } from 'react-router-dom'
import { EmptyState, PageHeader } from '../ui/index.ts'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'

export function NotFoundPage() {
  return (
    <section className={applicationClass("page")}>
      <PageHeader eyebrow="404" title="Page not found" summary="The requested control-plane route does not exist or has moved." />
      <EmptyState title="Nothing at this address" message="Return to the operational summary and continue from a known route." action={<Link className={applicationClass("primary-button")} to="/">Return to dashboard</Link>} />
    </section>
  )
}
