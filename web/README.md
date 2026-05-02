# Dependency Firewall UI

This app is the React + TypeScript + Vite control-plane UI for the multi-tenant firewall.

## Commands

```bash
npm install
npm run dev
npm run generate:api
npm run build
npm run lint
```

Recommended local validation:

```bash
npm run generate:api && npm run build && npm run lint
```

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
- `VITE_OPENAPI_URL` - OpenAPI JSON endpoint. Defaults to `/api/openapi.json`.
- `VITE_DEV_PROXY_TARGET` - Vite dev proxy target. Defaults to `http://localhost:8080`.
- `VITE_FIREWALL_ROOT_URL` - explicit firewall root used for npm and OCI client examples. Defaults to `http://localhost:8080` in local web development.

## Generated control-plane client workflow

- `npm run generate:api` exports the current Huma OpenAPI document from the Go codebase.
- The exported snapshot is committed at `openapi/control-plane.json`.
- The generated TypeScript bindings live at `src/lib/api/generated/openapi.ts`.
- Re-run `npm run generate:api` before `npm run build` or `npm run lint` after changing Go control-plane contracts so the UI compiles against the current API shape.
- `src/lib/api/client.ts` is the app-facing wrapper for base URLs, normalized API errors, tenant scoping, and future session header injection.
- React code should prefer `useSessionControlPlaneApi` or `useTenantControlPlaneApi` so auth/session and tenant concerns stay at the provider boundary instead of inside feature pages.

## Auth and session extension seams

No real authentication is implemented yet.

- `src/features/auth/AuthProvider.tsx` is the provider boundary for future session bootstrap and refresh logic.
- `src/features/auth/RouteGuard.tsx` and `useRouteGuard` are pass-through placeholders for future auth and RBAC enforcement.
- `src/features/auth/session.ts` is the single place to add bearer token or custom request header injection later.

## Tenant handling

- The app shell loads tenants from `GET /api/v1/tenants`, persists the active tenant in `localStorage`, and restores it on refresh.
- Tenant-scoped pages inject `X-Tenant-ID` through the shared control-plane client wrapper.
- Global endpoints such as `/healthz` and `GET /api/v1/policy-types` stay unscoped.
- Keep tenant-aware route behavior explicit in the UI so future auth and RBAC work can layer on top without changing feature page contracts.
