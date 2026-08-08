# Dependency Firewall UI redesign RFC

Status: accepted for implementation  
Reference experience: light theme  
Architecture: client-rendered React/Vite application

## Goals and principles

Dependency Firewall is an authenticated security operations console. The interface uses solid graphite navigation, warm neutral work surfaces, steel-blue actions, one-pixel borders, and restrained semantic colors. Elevation communicates overlays rather than decoration. IBM Plex Sans is the interface face; IBM Plex Mono is reserved for identifiers, hashes, versions, and commands. Neon, purple, glass effects, and speculative “futuristic” decoration are out of scope.

The reference layouts are 390, 768, 1024, and 1440 pixels wide. Every workflow must provide visible keyboard focus, WCAG 2.2 AA contrast, useful labels, reduced-motion behavior, and explicit loading, empty, error, disabled, destructive, warning, and success states.

## Component contract

The supported internal import surface is `web/src/ui/index.ts`:

- `foundation` owns tokens, typography, theme values, reset, motion, and breakpoints.
- `primitives` owns Button, IconButton, Badge, Panel, Field, Input, Select, Checkbox, Tabs, Tooltip, and Dialog.
- `patterns` owns PageHeader, Toolbar, MetricGrid, ResourceList, DefinitionList, FilterBar, EmptyState, and AsyncState.

UI code accepts data, callbacks, slots, native attributes, and renderable content. It must not import APIs, React Query, the router, tenant state, auth providers, or feature modules. Application composition belongs in layouts; domain behavior belongs in features. CSS Modules are the default for primitives, patterns, components, and features. Global CSS is limited to tokens, font declarations, reset, and document defaults after route migration is complete.

## Rendering and authentication

The console remains a React/Vite SPA. SSR adds operational complexity without an SEO or public-content benefit. Route modules remain lazy and D3 stays behind the dependency-graph route boundary. If public pages or measured first-render requirements emerge, React Router framework mode is the preferred migration path.

Clerk is not installed by this redesign. Features consume an application-owned auth contract with `loading`, `anonymous`, `authenticated`, `unauthorized`, and `error` states; provider-neutral identity, roles, and optional organization ID; asynchronous `getAccessToken()`; and optional sign-in, sign-out, and account-control slots. The API client awaits tokens and adds a bearer header. The Go backend remains the authority for authorization. A future Clerk adapter must validate short-lived session JWTs in Go using middleware or JWKS and must not trust client role claims. Dependency Firewall tenants remain separate from identity-provider organizations until a mapping is explicitly designed.

Browser globals are read behind runtime guards or component lifecycle boundaries so server rendering remains possible later. The existing theme storage key, `dependency-firewall-theme`, and tenant storage behavior are preserved.

## Route migration

The URLs and API payloads do not change.

1. Foundation: UI boundary, fonts/icons, auth/API contract, shell, responsive drawer, and browser-test foundation.
2. Core pages: Dashboard, Tenants, Upstreams, and Not Found use shared headers, metrics, resource lists, detail panels, forms, usage instructions, and async states.
3. Policy operations: Policies and Evaluations use shared filters, dense readable lists, dialogs, diffs, and wizards. The `unknown` dependency scope must round-trip unchanged.
4. Dependency intelligence: graph visuals adopt foundation tokens without changing drag, zoom, search, filtering, selection, connected-node highlighting, endpoint placement, or details. Remaining legacy global CSS is removed here.

## Playwright and CI

The normal suite intercepts `/api/v1/**` and `/healthz`, fixes tenant/auth data, and runs desktop and 390px mobile Chromium. Auth adapters cover anonymous, authenticated, unauthorized, and expired-session behavior. Selective captures cover the light dashboard shell, mobile navigation, dark shell, and graph default/selected states. Tests avoid timing-dependent data.

`npm run test:e2e` runs mocked tests; `npm run test:e2e:update` refreshes visual baselines; `npm run test:ui` opens Playwright UI. `npm run test:e2e:live` is a read-only smoke test gated by `PLAYWRIGHT_LIVE_BASE_URL` and a prepared tenant. CI runs `npm ci`, lint, build, mocked Playwright tests, and uploads the report on failure.

## Stack ownership

The stack is rooted at refreshed `main`:

- `ui-redesign/foundation`: this RFC, UI system, fonts/icons, auth-ready interfaces, async bearer tokens, shell, navigation, themes, and Playwright/CI foundation.
- `ui-redesign/core-pages`: Dashboard, Tenants, Upstreams, Not Found, and their route tests.
- `ui-redesign/policy-operations`: Policies, Evaluations, their dialogs/diffs/wizards, and policy/evaluation tests.
- `ui-redesign/dependency-intelligence`: dependency graph, final legacy-CSS removal, and graph interaction/visual tests.

Each PR links this RFC and lists owned components, routes, tests, and visual criteria. Every layer passes lint, TypeScript/Vite build, relevant Playwright and keyboard checks, and `git diff --check` before draft submission.

## Acceptance criteria

- Light and dark themes are coherent, readable, and retain the existing storage key.
- Navigation, tenant context, account context, and mobile drawer work with keyboard and pointer input.
- Auth-provider details do not escape the auth adapter and API token acquisition is asynchronous.
- All existing URLs, payloads, tenant behavior, policy semantics, and graph interactions remain intact.
- Loading, empty, error, disabled, destructive, warning, and success states use consistent components and language.
- Route chunks remain lazy; D3 is absent from the initial application chunk.
- Mocked desktop/mobile Playwright tests and the web CI workflow are deterministic.
