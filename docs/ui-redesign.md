# UI architecture and design guidance

The operator console is an implemented client-rendered React/TypeScript/Vite application. It is built and deployed separately from the Go runtime and consumes the control-plane API through generated OpenAPI types.

Current routes are Dashboard, Tenants, Upstreams, Policies, Evaluations, Dependency Graphs, and Not Found. Audit events have an API but no UI route.

## Current authentication boundary

The console is **not currently authenticated**. The local/default adapter returns an anonymous state, and route guards deliberately allow access while reporting placeholder session/role enforcement. Public Go HTTP routes do not validate bearer tokens or enforce RBAC.

Implemented extension seams are:

- provider-neutral loading, anonymous, authenticated, unauthorized, and error states;
- provider-neutral user, role, organization, sign-in/sign-out, and account-control fields;
- asynchronous `getAccessToken()`;
- API-client attachment of `Authorization: Bearer <token>` when a token exists;
- explicit route-guard and expired-session UI states.

These seams are not an authority boundary. A production IdP adapter, session enforcement, Go JWT/JWKS validation, RBAC, and IdP-organization-to-tenant mapping remain future work. Backend authorization must remain authoritative and must not trust client role claims.

## Product design principles

1. **Operational clarity before decoration.** Put scope, risk, state, and next action first.
2. **Calm by default, emphatic by exception.** Reserve semantic color for information that changes a decision.
3. **Progressive disclosure for dense systems.** Inventories support selection; details expose full records.
4. **Consistency is a safety feature.** Reuse the same control and state language across routes.
5. **Tenant context is explicit.** The shell always shows the active workspace.
6. **Keyboard and pointer behavior are peers.** Navigation, dialogs, filters, and graph inspection work without a mouse.
7. **Responsive means recomposed, not compressed.** Columns collapse and actions wrap rather than shrinking into illegibility.

The visual direction is restrained industrial security: graphite navigation, warm neutral work surfaces, steel-blue actions, one-pixel borders, and restrained status colors. Avoid neon, purple, glass-heavy, or speculative futuristic decoration.

## Visual system

Reusable values live in `web/src/ui/foundation/tokens.css`. Components consume semantic tokens; add a token only when it has a clear semantic role or multiple consumers.

- IBM Plex Sans: interface copy.
- IBM Plex Mono: identifiers, hashes, versions, coordinates, and commands.
- Borders establish grouping; shadows are mostly for overlays and drawers.
- Green, amber, and red indicate success, caution, and danger, always with text/icon support.
- Light theme is the reference; dark theme preserves hierarchy rather than merely inverting colors.
- Metrics use tabular figures with visible labels and units.
- Pills are reserved for compact status, badge, and filter roles.

## Responsive shell

- Desktop uses a 260px navigation rail and flexible content column.
- The rail stays visible while route content scrolls; avoid accidental overflow ancestors that break sticky positioning.
- The utility bar exposes tenant/account context separately from the page heading.
- Below 768px, navigation becomes a labelled modal drawer with a scrim, keyboard dismissal, expanded state, and focus recovery.
- Route content owns page height. Fixed heights are reserved for bounded surfaces such as the graph viewport.
- Verify behavior at 390, 768, 1024, and 1440 pixels.

## Reusable UI boundary

The supported import surface is `web/src/ui/index.ts`:

- `foundation`: tokens, typography, themes, reset, motion, breakpoints;
- `primitives`: domain-neutral controls such as Button, Badge, Panel, Field, and Input;
- `patterns`: reusable compositions such as PageHeader, ResourceList, EmptyState, and AsyncState.

Package-ready UI code accepts data, callbacks, slots, renderable content, and native attributes. It must not import APIs, React Query, router state, tenant state, auth providers, or feature modules.

Application composition lives in pages/layouts; domain behavior lives in `web/src/features`. CSS Modules are the default. Global CSS is limited to tokens, fonts, reset, and document defaults.

When a shared primitive or pattern replaces a route-specific implementation, remove superseded selectors, components, tokens, and tests in the same change.

## Route behavior

- **Dashboard:** summarize tenant protection and required setup; internal implementation metrics do not displace operator actions.
- **Tenants:** make the active workspace unmistakable and use shared creation dialog behavior.
- **Upstreams:** lead with source, ecosystem, credential readiness, policy coverage, and client setup.
- **Policies:** lead with plain-language effect, enabled/dry-run state, upstream scope, dependency target, and ordering. Technical schema/version data stays in details.
- **Evaluations:** lead with outcome, artifact, human-readable reason, and policy. Search/filter state must not blur page-level totals.
- **Dependency Graphs:** show root status/inventory, search, depth/type filters, D3 relationships, keyboard/pointer selection, zoom, and node/edge detail. Failed roots keep errors visible.

Loading, empty, error, disabled, destructive, warning, and success states use explicit language. Disabled controls explain non-obvious reasons. Destructive actions require proportional confirmation.

## Rendering and performance

Routes are lazy-loaded. D3 remains behind the dependency-graph route boundary and must not enter the initial chunk. Avoid module-scope browser reads; guard them or use lifecycle boundaries.

SSR is intentionally deferred because the console has no public SEO/content requirement. Consider React Router framework mode only if public pages or measured first-render needs create a concrete trigger.

Theme storage uses `dependency-firewall-theme`; tenant selection remains persisted by the application tenant boundary.

## Accessibility

- Maintain WCAG 2.2 AA contrast in both themes.
- Provide logical tab order and visible `:focus-visible` treatment.
- Give icon-only controls accessible names and hide decorative icons.
- Associate form labels, hints, validation, required state, and errors programmatically.
- Use live regions for meaningful state changes without announcing static content repeatedly.
- Respect `prefers-reduced-motion`.
- Never communicate risk, selection, or graph relationships through color alone.
- Dialogs have labelled titles, contained focus, predictable dismissal, and consistent action order.

## Playwright strategy

`npm run test:e2e` runs deterministic mocked desktop and 390px mobile Chromium projects. Tests intercept `/api/v1/**` and `/healthz`, fix tenant/auth data, and cover core workflows plus anonymous/authenticated/unauthorized/expired adapter states.

Selective screenshots cover stable shell and graph states. Behavioral assertions remain primary: prefer roles, labels, keyboard input, and observable layout/interaction outcomes. Use `data-*` selectors only when generated SVG or CSS-module output has no stable accessible selector.

`npm run test:e2e:live` is an optional read-only smoke test gated by `PLAYWRIGHT_LIVE_BASE_URL` and a prepared tenant.

## Review checklist

- Tenant, resource state, and primary action are clear.
- Existing primitives/patterns are reused where appropriate.
- Light/dark and desktop/mobile layouts remain coherent.
- Affected async, empty, error, disabled, and success states are represented.
- Keyboard operation, focus, labels, contrast, and reduced motion remain correct.
- Styling lives with its owner and obsolete styling is removed.
- Route lazy loading and the D3 boundary remain intact.
- `npm run lint`, `npm run build`, relevant Playwright tests, and `git diff --check` pass.

## Possible future work

- real Clerk/OIDC adapter and session bootstrap;
- backend bearer validation and RBAC;
- identity-provider organization mapping;
- an Audit Events UI route;
- SSR/framework mode only after a concrete product or performance trigger.
