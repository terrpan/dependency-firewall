# Dependency Firewall UI

This app is the React + TypeScript + Vite control-plane UI for the multi-tenant firewall.

The visual principles, component boundaries, responsive behavior, accessibility requirements, and UI review checklist are documented in [`docs/ui-redesign.md`](../docs/ui-redesign.md).

## Commands

```bash
npm install
npm run dev
npm run generate:api
npm run build
npm run lint
npm run test:e2e
```

Recommended local validation for UI changes:

```bash
npm run lint && npm run build && npm run test:e2e
```

Run `npm run generate:api` first when a control-plane API contract changed.

## Local development

1. Start the backend stack from the repository root with `make up` or run the Go server locally on `http://localhost:8080`.
2. Install dependencies with `npm install`.
3. Regenerate the typed API client with `npm run generate:api` whenever control-plane request DTOs, response DTOs, or policy type metadata change in Go.
4. Start Vite with `npm run dev`.
5. Open the printed local URL from Vite.

The dev server proxies `/api` requests to `VITE_DEV_PROXY_TARGET` (default `http://localhost:8080`), so the UI can talk to the control-plane API without changing route code.

## Environment

- `VITE_API_BASE_URL` - control-plane REST base URL. Defaults to `/api/v1`.
- `VITE_DOCS_URL` - docs endpoint. Defaults to `/api/docs`.
- `VITE_DEV_PROXY_TARGET` - Vite dev proxy target. Defaults to `http://localhost:8080`.
- `VITE_FIREWALL_ROOT_URL` - explicit firewall root used for npm and OCI client examples. Defaults to `http://localhost:8080` in local web development.
- `VITE_OTEL_ENABLED` - enable browser OpenTelemetry tracing. Defaults to `false`.
- `VITE_OTEL_EXPORTER_URL` - OTLP/HTTP protobuf trace export URL. Defaults to `/otlp/v1/traces` in Vite dev and `http://localhost:4318/v1/traces` otherwise.
- `VITE_OTEL_DEV_PROXY_TARGET` - Vite dev proxy target for browser OTLP export. Defaults to `http://localhost:4318`.
- `VITE_OTEL_SERVICE_NAME` - browser service name reported to the collector. Defaults to `dependency-firewall-web`.
- `VITE_OTEL_SAMPLE_RATIO` - browser trace sampling ratio. Defaults to `1`.

## Generated control-plane client workflow

- `npm run generate:api` exports the current Huma OpenAPI document from the Go codebase.
- The exported snapshot is committed at `openapi/control-plane.json`.
- The generated TypeScript bindings live at `src/lib/api/generated/openapi.ts`.
- Re-run `npm run generate:api` before `npm run build` or `npm run lint` after changing Go control-plane contracts so the UI compiles against the current API shape.
- `src/lib/api/client.ts` is the app-facing wrapper for base URLs, normalized API errors, tenant scoping, and future session header injection.
- `src/lib/api/client.ts` also owns browser-side trace propagation for control-plane requests.
- React code should prefer `useSessionControlPlaneApi` or `useTenantControlPlaneApi` so auth/session and tenant concerns stay at the provider boundary instead of inside feature pages.

## Browser tracing

When `VITE_OTEL_ENABLED=true`, the UI emits spans for:

- route navigation, including the initial page load
- shared control-plane API requests
- mutation flows routed through the shared API client, including create, update, delete, import, rollback, and cache-clear operations

Example local setup with Aspire:

```bash
docker compose --profile observability up -d otel-collector aspire-dashboard

VITE_OTEL_ENABLED=true \
npm run dev
```

In Vite development, the browser exporter defaults to `/otlp/v1/traces` and the dev server proxies that to the local collector. Outside Vite dev, the frontend defaults to `http://localhost:4318/v1/traces`, so the UI can run as a separate service and still export traces directly through the collector into Aspire.

If you want the UI to run independently from the control-plane, keep or set:

```bash
VITE_OTEL_EXPORTER_URL=http://localhost:4318/v1/traces
```

The collector is the browser-facing OTLP endpoint. In Vite dev, the config normalizes that back through the `/otlp` proxy, but you still need to **restart `npm run dev`** after changing tracing env vars.

## Auth and session extension seams

The local adapter does not integrate an external identity provider yet. The application boundary is provider-neutral so Clerk or another OIDC provider can be added without leaking provider APIs into features.

- `src/features/auth/AuthProvider.tsx` owns session bootstrap and the active adapter.
- `src/features/auth/adapter.ts` defines loading, anonymous, authenticated, unauthorized, and error states plus provider-neutral identity and account actions. An expired test session maps to the error state and recovery experience.
- `src/features/auth/RouteGuard.tsx` renders explicit authentication and authorization states.
- `getAccessToken()` is asynchronous. `src/lib/api/client.ts` awaits it and attaches `Authorization: Bearer <token>` without knowing the identity provider.
- Authorization remains enforced by the Go backend; client roles are presentation context, not an authority boundary.
- Dependency Firewall tenants remain independent from identity-provider organizations until an explicit mapping is designed.

## Tenant handling

- The app shell loads tenants from `GET /api/v1/tenants`, persists the active tenant in `localStorage`, and restores it on refresh.
- Tenant-scoped pages inject `X-Tenant-ID` through the shared control-plane client wrapper.
- Global endpoints such as `/healthz` and `GET /api/v1/policy-types` stay unscoped.
- Keep tenant-aware route behavior explicit in the UI so future auth and RBAC work can layer on top without changing feature page contracts.

## UI architecture

- Import reusable UI only through `src/ui/index.ts`.
- `src/ui/foundation` owns tokens, reset, shared application styling, themes, and typography.
- `src/ui/primitives` contains provider- and domain-neutral controls.
- `src/ui/patterns` contains reusable page-level presentation patterns.
- Feature modules own domain behavior and route-specific CSS Modules. UI primitives and patterns must not import APIs, React Query, routing, tenant state, auth providers, or features.
- Route modules remain lazy. D3 is isolated to the dependency-graph route.
- Global CSS is limited to tokens, reset, fonts, and document defaults.

See the [UI RFC and review checklist](../docs/ui-redesign.md) before introducing a new component, token, layout convention, or responsive behavior.

## Browser tests

- `npm run test:e2e` runs deterministic mocked desktop and mobile Chromium projects.
- `npm run test:e2e:update` updates selective visual baselines.
- `npm run test:ui` opens Playwright's interactive runner.
- `npm run test:e2e:live` runs the optional read-only live smoke project when `PLAYWRIGHT_LIVE_BASE_URL` and a prepared tenant are available.
- Mocked tests intercept `/api/v1/**` and `/healthz`. Prefer roles and labels; use stable `data-*` state for generated SVG elements when an accessible selector is unavailable.
