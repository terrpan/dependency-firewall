# Adding an upstream or ecosystem

## Goal

Add support for a new upstream protocol or ecosystem without breaking core policy invariants, runtime boundaries, or tenant isolation.

## Decide the scope first

Most changes are one of these:

1. New upstream **instance** only (no code change).
2. New upstream **capability** for an existing ecosystem.
3. New upstream **protocol/ecosystem** (new delivery + infra + domain support).

Treat (2) and (3) as extension work. Keep behavior explicit and compiled-in.

## Extension rules

- Keep policy and evaluation logic in `internal/core`.
- Keep delivery adapters (`internal/delivery/*`) focused on protocol parsing/rendering and request orchestration.
- Keep upstream network/auth implementations in `internal/infra/upstream/*`.
- Do not add dynamic plugins or `init()` registration.
- Preserve tenant and upstream scoping in caches, auth, and audit flows.

For protocol adapter request/response flow details, see `docs/proxy-behavior.md`.

## Checklist

### 1. Extend domain vocabulary explicitly

Update domain constants and capability rules:

- `internal/core/domain/ecosystem.go`
  - add `domain.EcosystemType` values when introducing a new ecosystem
- `internal/core/domain/upstream_capability.go`
  - add new `domain.UpstreamCapability` constants
  - update `allowedUpstreamCapabilities`
  - verify `DefaultUpstreamCapabilities` and legacy-default behavior remain intentional

If capability semantics are user-facing, document them in `docs/policy-engine.md`.

### 2. Keep policy compatibility declarative

Policy compatibility must stay data-driven via policy definitions:

- update policy definition providers in `internal/core/policy/catalog_*.go`
  - `SupportedEcosystems`
  - `RequiredCapabilities`
  - `requiresExternalMetadata` (only when external enrichment is needed)
- keep provider registration explicit in `internal/core/policy/catalog.go` (`policyDefinitionProviders`)

Validation and filtering consume these descriptors, so avoid adding new ecosystem/capability switches in services.

### 3. Implement upstream client responsibilities in infrastructure

If a new protocol client is needed, implement `port.UpstreamClient` behavior in `internal/infra/upstream/*`:

- `FetchMetadata`
- `FetchContent`
- `ResolveReference`

Rules:

- keep auth handling server-side and scoped to configured upstream credentials
- keep error surfaces short and domain-safe
- keep per-tenant/per-upstream isolation in cache keys and request flow
- implement `ResolveReference` for mutable or alias references when the ecosystem has them, so policy evaluation can use a concrete version or immutable reference where possible
- do not leak delivery concerns into infra code

### 4. Add or extend delivery adapter responsibilities

For a new protocol adapter (or major route extension), add/update handler logic under `internal/delivery/<protocol>/`:

- parse protocol-specific request shape
- resolve `tenant_id` and `upstream_id`
- normalize into `domain.AccessRequest`
- call `AccessService.Evaluate`
- render protocol-compatible allow/deny responses
- keep audit hooks and correlation behavior consistent

Delivery should not call repositories directly.

### 5. Preserve core evaluation invariants

When extending upstream support, do not change these invariants unless intentionally scoped:

- deny overrides allow
- unknown policy type/evaluation errors fail closed as deny
- enrichment runs only when enabled policies require external metadata
- version-sensitive enrichment and decision caching only run for requests that identify a concrete artifact version, digest, or resolver-backed immutable reference
- package-document/listing requests that do not identify a single enforceable artifact version should bypass external enrichment and decision-cache lookup/write, while still allowing artifact-only policies to run
- policy evaluation stays local to the proxy request path (no per-request control-plane policy RPC)

If behavior must change, update docs and tests in the same PR.

### 6. Update control-plane/API surface when needed

When ecosystem or capability values become externally visible:

- update control-plane DTO mapping and validation for upstream create/update
- verify `/api/v1/policy-types` compatibility hints still reflect actual support
- regenerate web API types if contract fields/enums changed:

```bash
npm --prefix web run generate:api
```

### 7. Add focused tests before broad tests

Minimum expected coverage:

- domain capability normalization and defaults
- policy/upstream compatibility validation (`internal/core/policy`)
- delivery adapter behavior for tenant/upstream resolution and deny/allow flow
- infra upstream client behavior for auth/challenge/error handling

Then run:

```bash
go test ./internal/core/policy ./internal/core/service
go test ./...
```

### 8. Update docs in the same PR

At minimum:

- `docs/policy-engine.md` for capability/evaluation semantics
- `docs/architecture.md` if boundaries or flow changed
- `docs/proxy-behavior.md` for protocol-specific request behavior
- `README.md` when user-facing setup changes

## Practical file map

For most upstream extension PRs, expect edits in some subset of:

- `internal/core/domain/ecosystem.go`
- `internal/core/domain/upstream_capability.go`
- `internal/core/policy/catalog_*.go`
- `internal/core/policy/catalog.go`
- `internal/core/policy/upstream_support.go`
- `internal/delivery/<protocol>/handler.go`
- `internal/infra/upstream/*.go`
- `docs/policy-engine.md`
- `docs/architecture.md`
- `docs/proxy-behavior.md`
- `README.md`
