import { Suspense, type ComponentType, type LazyExoticComponent } from 'react'
import { applicationClass } from '../ui/foundation/applicationStyles.ts'
import { PageHeader } from '../ui/index.ts'

function RouteLoadingFallback() {
  return (
    <section className={applicationClass("page")}>
      <PageHeader eyebrow="Loading" title="Loading page" summary="Preparing the requested view." />
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
