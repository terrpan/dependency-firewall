# Dependency Firewall UI redesign RFC

Status: implemented

Reference experience: light theme

Architecture: client-rendered React/Vite application

## Goals and principles

Dependency Firewall is an authenticated security operations console. The interface uses solid graphite navigation, warm neutral work surfaces, steel-blue actions, one-pixel borders, and restrained semantic colors. Elevation communicates overlays rather than decoration. IBM Plex Sans is the interface face; IBM Plex Mono is reserved for identifiers, hashes, versions, and commands. Neon, purple, glass effects, and speculative “futuristic” decoration are out of scope.

The reference layouts are 390, 768, 1024, and 1440 pixels wide. Every workflow must provide visible keyboard focus, WCAG 2.2 AA contrast, useful labels, reduced-motion behavior, and explicit loading, empty, error, disabled, destructive, warning, and success states.

## Product design principles

1. **Operational clarity before decoration.** Put the current scope, risk, state, and next action ahead of branding or visual novelty. Every screen should answer where the operator is, what needs attention, and what can be done next.
2. **Calm by default, emphatic by exception.** Neutral surfaces carry normal work. Semantic color is reserved for information that changes a decision: success, warning, destructive action, or active selection.
3. **Progressive disclosure for dense systems.** Lists and summaries expose the fields needed to choose an item. Panels, dialogs, and graph details expose the full record without making the inventory unreadable.
4. **Consistency is a safety feature.** The same action, state, and resource type should look and behave the same across routes. Prefer an existing primitive or pattern before adding a route-specific control.
5. **The tenant is always explicit.** Tenant context remains visible in the shell and tenant-scoped work must never rely on an operator remembering an earlier selection.
6. **Keyboard and pointer behavior are peers.** Focus, selection, dismissal, navigation, graph inspection, and form submission must be complete without a mouse.
7. **Responsive means re-composed, not compressed.** Columns collapse, actions wrap, and navigation becomes a drawer. Information must not become illegible merely to preserve a desktop arrangement.

## Visual language

### Color and elevation

- Warm neutral canvas and white/light-neutral surfaces are the light-theme reference.
- The graphite navigation rail establishes application context. On desktop it remains pinned to the viewport while long route content scrolls; on mobile it becomes a fixed modal drawer with a scrim.
- Steel blue identifies primary actions, active navigation, links, and interactive focus. It is not used as ambient decoration.
- Green, amber, and red communicate success, caution, and danger respectively. Never use color as the only state indicator; pair it with text, an icon, or both.
- Borders establish grouping. Shadows are limited to overlays, drawers, menus, and the light separation required for raised panels.
- Dark theme preserves the same hierarchy and semantics rather than simply inverting colors.

All reusable values belong in `web/src/ui/foundation/tokens.css`. Components must consume semantic tokens instead of introducing unexplained hex values. A new token needs more than one credible consumer or a documented semantic role.

### Typography and data

- IBM Plex Sans is used for interface copy. IBM Plex Mono is limited to identifiers, hashes, versions, package coordinates, and commands.
- Page titles describe the resource or operation. Eyebrows provide short context and are not substitutes for headings.
- Numeric metrics use tabular figures. Labels and units remain visible so a number is not presented without meaning.
- Sentence case is the default for headings, labels, buttons, tabs, and status copy.
- Dense data should remain scannable through alignment, spacing, and grouping; reducing the font size is the last resort.

### Spacing, shape, and density

- Use foundation spacing tokens and the shared `Panel`, `ResourceList`, `MetricGrid`, and `DefinitionList` patterns before adding one-off layout values.
- One-pixel borders and modest radii are the default. Pills are reserved for badges, compact filters, and statuses.
- Primary actions appear once per local decision area. Secondary actions must not compete visually with the primary action.
- Action color is semantic across routes: steel blue advances or creates, neutral surfaces cancel, refresh, or navigate, and restrained red identifies destructive actions.
- Destructive actions require explicit wording and confirmation proportional to their impact.

## Shell and responsive behavior

- The desktop shell is a two-column grid with a 260px navigation rail and a flexible content column.
- The rail uses viewport-sticky positioning. Ancestors of a sticky element must not introduce clipping or scrolling through `overflow: hidden`, `auto`, or `scroll` unless that ancestor is intentionally the scroll container.
- The utility bar remains visible while route content scrolls and exposes tenant/account context without displacing the page heading.
- Below 768px, navigation is a fixed drawer. Opening and closing it must work by keyboard, expose an accessible expanded state, and restore a usable focus path.
- Route content owns vertical page growth. Avoid fixed content heights except for bounded interactive surfaces such as the graph viewport.
- Test meaningful behavior at 390px, 768px, 1024px, and 1440px; do not infer mobile behavior solely from desktop resizing.

## Interaction and state language

- Loading states say what is loading and preserve surrounding context where possible.
- Empty states explain why the area is empty and provide a useful next action when one exists.
- Error states describe the failed operation, avoid leaking implementation details, and offer retry or recovery when safe.
- Disabled controls need an adjacent explanation when the reason is not obvious from context.
- Success feedback confirms the completed operation without interrupting the next task.
- Dashboards summarize tenant protection with decision, enforcement, and upstream counts once; then prioritize required setup, blocks, and warnings. Internal service health and implementation details such as cache ratios do not compete with tenant actions.
- Tenant inventories make the active workspace unmistakable, describe context changes as switching rather than opening, and reveal the creation form on request. When no tenant exists, creation becomes the immediate inline recovery path.
- Upstream inventories lead with source, ecosystem, credential readiness, and available policy coverage. Client setup is the primary next action after selection; identifiers and timestamps are progressively disclosed, removal is confirmed inline, and generated setup must never recommend weakening transport security.
- Policy inventories lead with a plain-language effect, enforcement state, upstream scope, dependency target, and evaluation order. Schema, identifiers, versions, and timestamps are progressively disclosed in details rather than competing with the rule itself.
- Evaluation history leads with the outcome, artifact, human-readable reason, and responsible policy. Page-level signals stay separate from filtered row counts; combined filters narrow results predictably, while hashes, identifiers, cache timestamps, and secondary matches remain progressively disclosed.
- Dependency graphs explain direct and transitive package relationships before exposing graph identifiers or hashes. Completed roots are preferred by default, failed roots keep their actionable error visible, map targets have equivalent keyboard and pointer semantics, and selected details never reduce the usable graph viewport.
- Disabled and dry-run policies describe what they would do, never what they currently enforce.
- Dialogs have a labelled title, a predictable dismissal path, contained focus, and an action order consistent across features.
- Selection must remain visually distinct from hover and keyboard focus. Graph nodes and edges expose the same selection behavior to Enter/Space and pointer activation.

## Component contract

The supported internal import surface is `web/src/ui/index.ts`:

- `foundation` owns tokens, typography, theme values, reset, motion, and breakpoints.
- `primitives` owns Button, IconButton, Badge, Panel, Field, Input, Select, Checkbox, Tabs, Tooltip, and Dialog.
- `patterns` owns PageHeader, Toolbar, MetricGrid, ResourceList, DefinitionList, FilterBar, EmptyState, and AsyncState.
- Every route and route-level loading, empty, or error state uses `PageHeader` for its eyebrow, `h2` title, summary, and actions. Routes must not recreate page-header typography or responsive layout in feature CSS.

UI code accepts data, callbacks, slots, native attributes, and renderable content. It must not import APIs, React Query, the router, tenant state, auth providers, or feature modules. Application composition belongs in layouts; domain behavior belongs in features. CSS Modules are the default for primitives, patterns, components, and features. Global CSS is limited to tokens, font declarations, reset, and document defaults after route migration is complete.

### Styling ownership and cleanup

- A component or feature owns its CSS Module. Shared application compositions live in `ui/foundation/Application.module.css`; reusable controls belong in their primitive or pattern module.
- Class-name helpers may combine a feature module with shared application classes, but must not become a second undocumented public UI API.
- Do not add route rules to `index.css`, `reset.css`, or `tokens.css`.
- When a route adopts a primitive or pattern, delete the superseded selectors, tokens, components, and tests in the same change. Do not retain speculative compatibility CSS.
- Before removing a dynamic class, account for generated names such as semantic tones. Verify deletion with lint, a production build, and the affected browser workflows.
- Avoid module-scope browser reads. Layout behavior should be expressed in CSS unless JavaScript is required for interaction state.

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

Browser tests should prefer roles, labels, and user-visible names. Use `data-testid` or `data-*` state only where generated SVG/CSS-module output lacks a stable accessible selector. Layout regressions require behavioral assertions—for example, scrolling a tall page and measuring a sticky rail—rather than screenshots alone. Screenshots remain selective and support review; they are not the only acceptance mechanism.

## Accessibility requirements

- Maintain WCAG 2.2 AA contrast in both themes, including muted text, focus indicators, badges, and disabled states.
- Every interactive element is reachable in a logical tab order and has a visible `:focus-visible` treatment.
- Icon-only controls have accessible names. Decorative icons are hidden from assistive technology.
- Forms associate labels, hints, validation messages, and errors with their controls. Required state is communicated programmatically.
- Status changes use an appropriate live region without repeatedly announcing static content.
- Respect `prefers-reduced-motion`; motion must not be necessary to understand state or location.
- Do not communicate risk, selection, or graph relationships through color alone.

## Review checklist

Before merging a UI change, confirm:

- The tenant, resource state, and primary action are clear.
- Existing primitives and patterns were reused where appropriate.
- Light/dark and desktop/mobile layouts remain coherent.
- Loading, empty, error, disabled, and success paths affected by the change are represented.
- Keyboard operation, focus visibility, labels, and reduced motion remain correct.
- New styling is in the owning CSS Module and obsolete styling was deleted.
- Route lazy loading and the D3 route boundary remain intact.
- Relevant Playwright workflows, `npm run lint`, `npm run build`, and `git diff --check` pass.

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
