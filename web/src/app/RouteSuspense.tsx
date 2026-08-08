import { Suspense, type ComponentType, type LazyExoticComponent } from 'react'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'

function RouteLoadingFallback() {
  return (
    <section className={applicationClass("page")}>
      <header className={applicationClass("page-header")}>
        <div>
          <p className={applicationClass("eyebrow")}>Loading</p>
          <h2>Loading page</h2>
          <p className={applicationClass("page-summary")}>Preparing the requested view.</p>
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
