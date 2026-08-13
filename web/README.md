# Dependency Firewall UI

This directory contains the separately served React/TypeScript/Vite control-plane client. The Go runtime does not serve `web/dist`.

See [UI architecture and design guidance](../docs/ui-redesign.md) for component boundaries, responsive behavior, accessibility, and review rules.

## Current routes

- `/`: Dashboard
- `/tenants`
- `/upstreams`
- `/policies`
- `/evaluations`
- `/dependency-graphs`

Audit events are available at `/api/v1/audit/events` but do not have a UI route.

## Commands

```bash
npm ci
npm run dev
npm run generate:api
npm run lint
npm run build
npm run test:e2e
```

Run `generate:api` only when the Go control-plane contract or exported policy metadata changes; documentation-only changes must not regenerate the snapshot or TypeScript bindings.

## Local development

1. Start the backend from the repository root with `make up`, or run all-in-one on `http://localhost:8080`.
2. Run `npm ci`.
3. Run `npm run dev` and open the printed Vite URL.

Vite proxies `/api` to `VITE_DEV_PROXY_TARGET`, defaulting to `http://localhost:8080`.

For a deployable asset build:

```bash
npm ci
npm run build
```

Serve `dist/` through a static host and route API requests to the control plane.

## Environment

- `VITE_API_BASE_URL`: REST base URL, default `/api/v1`.
- `VITE_DOCS_URL`: API docs URL, default `/api/docs`.
- `VITE_DEV_PROXY_TARGET`: Vite API proxy, default `http://localhost:8080`.
- `VITE_FIREWALL_ROOT_URL`: proxy root used in supported-ecosystem client examples.
- `VITE_OTEL_ENABLED`: enables browser tracing, default `false`.
- `VITE_OTEL_EXPORTER_URL`: OTLP/HTTP protobuf endpoint.
- `VITE_OTEL_DEV_PROXY_TARGET`: Vite OTLP proxy target, default `http://localhost:4318`.
- `VITE_OTEL_SERVICE_NAME`: browser service name, default `dependency-firewall-web`.
- `VITE_OTEL_SAMPLE_RATIO`: root sampling ratio, default `1`.

## Generated API client

- `npm run generate:api` exports Huma OpenAPI into `openapi/control-plane.json`.
- Generated TypeScript lives in `src/lib/api/generated/openapi.ts`.
- `src/lib/api/client.ts` owns base URLs, normalized errors, tenant headers, bearer-token attachment, and browser trace propagation.
- Feature code should use `useSessionControlPlaneApi` or `useTenantControlPlaneApi` rather than constructing clients directly.

## Authentication status

The UI and Go public HTTP routes are currently unauthenticated.

The default `localAuthAdapter` returns anonymous. `RouteGuard` renders the session/role state seams but intentionally permits access even when a requested session or role is absent. Tenant selection and `X-Tenant-ID` are not authorization.

Implemented seams:

- provider-neutral auth/session state;
- asynchronous `getAccessToken()`;
- `Authorization: Bearer <token>` attachment when the adapter returns a token;
- sign-in, sign-out, account-control, role, and organization extension fields;
- explicit anonymous, unauthorized, expired, and error UI states used in browser tests.

Not implemented:

- Clerk/OIDC provider integration;
- enforced browser sessions or UI roles;
- Go bearer-token validation/JWKS middleware;
- RBAC or user-to-tenant membership authorization.

The browser must never be treated as the authorization authority. A future adapter requires corresponding backend token validation and role/tenant checks.

## Tenant handling

- The shell loads tenants from `GET /api/v1/tenants`.
- Active tenant selection is persisted in local storage.
- Tenant-scoped hooks attach `X-Tenant-ID`.
- Health and policy-type catalog requests remain global.

These mechanisms provide UI context and repository scoping only; they do not authenticate the operator.

## UI boundary

- Import reusable UI through `src/ui/index.ts`.
- `src/ui/foundation` owns tokens, reset, themes, typography, and shared application styles.
- `src/ui/primitives` contains provider- and domain-neutral controls.
- `src/ui/patterns` contains reusable presentation compositions.
- Feature modules own domain behavior and route CSS Modules.
- Reusable UI must not import API clients, React Query, routing, tenant/auth providers, or features.
- Routes remain lazy and D3 stays isolated to Dependency Graphs.

## Browser tracing

With `VITE_OTEL_ENABLED=true`, the UI emits route-navigation and shared API-client spans. In Vite development the exporter defaults to `/otlp/v1/traces`, proxied to the local collector. Restart Vite after changing trace environment variables.

## Browser tests

- `npm run test:e2e`: deterministic mocked desktop/mobile Chromium suite.
- `npm run test:e2e:update`: update selective screenshots.
- `npm run test:ui`: interactive Playwright UI.
- `npm run test:e2e:live`: optional read-only smoke test with `PLAYWRIGHT_LIVE_BASE_URL` and prepared tenant.

Mocked tests intercept `/api/v1/**` and `/healthz`. Prefer roles, labels, keyboard behavior, and stable application state over implementation selectors.
