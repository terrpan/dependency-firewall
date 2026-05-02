import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Route missing</p>
          <h2>Page not found</h2>
          <p className="page-summary">
            This route is outside the current scaffold. Return to the dashboard and continue from
            the existing control-plane shell.
          </p>
        </div>
      </header>

      <section className="card">
        <p>
          Go back to the <Link className="inline-link" to="/">dashboard</Link>.
        </p>
      </section>
    </section>
  )
}
