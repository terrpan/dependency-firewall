type PlaceholderPageProps = {
  title: string
  description: string
  nextSteps: readonly string[]
}

export function PlaceholderPage({
  title,
  description,
  nextSteps,
}: PlaceholderPageProps) {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Control-plane surface</p>
          <h2>{title}</h2>
          <p className="page-summary">{description}</p>
        </div>
        <span className="status-pill">Scaffold</span>
      </header>

      <div className="page-grid">
        <section className="card">
          <h3>Current shell support</h3>
          <p className="muted">Tenant selection stays in the shared shell for tenant-scoped routes.</p>
          <ul className="list compact-list">
            <li>Keep tenant switching in the shell instead of repeating it inside each page.</li>
            <li>Use this screen for discovery, management, and validation flows.</li>
          </ul>
        </section>

        <section className="card">
          <h3>Next slice</h3>
          <ul className="list">
            {nextSteps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  )
}
