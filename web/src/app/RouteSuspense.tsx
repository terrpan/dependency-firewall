import { Suspense, type ComponentType, type LazyExoticComponent } from 'react'

function RouteLoadingFallback() {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <p className="eyebrow">Loading</p>
          <h2>Loading page</h2>
          <p className="page-summary">Preparing the requested view.</p>
        </div>
      </header>
    </section>
  )
}

type RouteElementProps = {
  Page: LazyExoticComponent<ComponentType>
}

export function RouteElement({ Page }: RouteElementProps) {
  return (
    <Suspense fallback={<RouteLoadingFallback />}>
      <Page />
    </Suspense>
  )
}
