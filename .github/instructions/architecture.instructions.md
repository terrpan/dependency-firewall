---
applyTo: "cmd/**/*.go,internal/**/*.go,docs/**/*.md"
description: "Repository-specific layering and naming rules for dependency-firewall"
---

# Dependency Firewall Architecture Instructions

Allways follow the architecture rules and naming conventions described in this file when adding or modifying code in the repository. These rules are designed to maintain a clean separation of concerns, ensure consistent naming, and support the multi-tenant nature of the service.

Consult the `docs/architecture.md` file for a detailed overview of the system architecture. And when core functionality is updaded or added, the `docs/architecture.md` file must be updated to reflect the changes. The architecture documentation should always be kept up to date with the codebase to ensure it accurately reflects the current design and implementation of the system.

## Layer boundaries

- Delivery handlers must call **core services**, not repositories, parser packages, or evaluator packages directly.
- Delivery is responsible for HTTP/protocol parsing and response rendering only.
- Huma is a delivery-layer concern only. Use it for control-plane OpenAPI/docs generation plus typed request/response modeling at the boundary.
- Huma remains limited to control-plane handlers. The current Huma-backed control-plane set includes health, tenants, policy CRUD, policy version history, policy rollback, policy type listing, policy import, evaluation listing, decision-cache clearing, and upstream CRUD.
- Do not introduce Huma into `internal/delivery/npm` or `internal/delivery/oci` unless the architecture docs are explicitly updated for that expansion.
- OCI tenant routing for Docker-compatible traffic should prefer hostname-based resolution at the delivery boundary. Keep `X-Tenant-ID` support only as a direct-test or non-Docker fallback.
- Treat Huma endpoint coverage as human-controlled. Do not document or assume a control-plane endpoint is Huma-backed unless that endpoint has been explicitly migrated in code.
- Delivery request payloads must decode into delivery-layer request DTOs. Do not decode JSON directly into domain models.
- Boundary formats such as JSON and YAML must be decoded into typed structs before entering core workflows.
- Use declarative validation libraries at delivery/config boundaries when they reduce boilerplate, but keep business invariants in explicit typed-domain validation.
- Delivery response DTOs belong in delivery. Do not add JSON response tags to core types just to support an HTTP handler.
- Do not let Huma request, response, operation, or OpenAPI types cross into core or infrastructure packages.
- Do not return raw PostgreSQL, Valkey, or driver errors to API clients. Translate infrastructure failures to domain-safe errors, log the detailed cause server-side, and return short human-readable API messages.
- Core services orchestrate workflows across repositories, caches, enrichers, and policy evaluation.
- Infrastructure implements ports. It must not contain policy logic or HTTP handler behavior.
- OCI artifact caching must remain tenant-aware across lookup, writes, cleanup, and future backend extensions. Do not add cross-tenant cache reuse as an implicit shortcut.
- Do not expose filesystem-style abstractions such as `fs.FS` from core for OCI artifact caching. Model cache behavior as a core port and keep storage details in infrastructure.

## Shared port naming

- Ports used by more than one ecosystem must use **protocol-neutral** names.
- Avoid OCI-specific names such as `manifest`, `blob`, and `tag` in shared core ports and shared core services.
- Use neutral terms such as `metadata`, `content`, and `reference` in shared abstractions.
- Ecosystem-specific terminology belongs in `internal/delivery/npm`, `internal/delivery/oci`, and ecosystem-specific infrastructure packages.

## Policy engine rules

- The evaluator is **deny-wins**. Do not document or implement allow rules as bypassing later deny rules unless the evaluator semantics are intentionally changed everywhere.
- Keep policy evaluation pure: no HTTP, no PostgreSQL, no Valkey, no upstream calls inside policy packages.
- Core policy config must use typed config structs per policy type. Do not pass `map[string]any` through core services, repositories, or evaluators.
- Reject unknown policy config fields and wrong types at the decode/validation boundary instead of tolerating them implicitly.
- Policy schema changes must be explicit and versioned. Use per-policy-item `schema_version` plus PostgreSQL data migrations rather than long-lived runtime compatibility for deprecated fields. Schema compatibility must be defined per policy type in core so one policy kind can evolve without forcing unrelated kinds to bump.
- Persisted deprecated or unsupported policy schema data must surface short upgrade-style errors to users and must not leak raw storage/decode failures.
- Policy rollback must restore from retained policy snapshots, not by reconstructing partial state from current rows.
- For approved-license policies, keep missing license metadata behavior explicit. The current `license_allowlist` policy must fail closed when license metadata is unavailable.
- Policy create, update, delete, and import workflows must invalidate the tenant decision cache immediately so stale allow/deny decisions are not served after a policy change.
- Policy-set SHA-256 values are for audit and traceability. Do not replace tenant cache generation invalidation with policy hashes on the runtime decision-cache hot path.
- License policies should use **SPDX identifiers** as their vocabulary. Keep SPDX mapping/normalization at the enrichment or condition edge, not in delivery handlers.

## Naming

- Prefer names that describe business responsibility, not transport mechanics.
- Avoid generic exported type names like `Handler` when a more specific name exists.
- Prefer names like `AccessService`, `PolicyService`, `RegistryHandler`, and `EvaluationService` over ambiguous names.

## Multi-tenancy

- Every tenant-owned workflow must carry `tenant_id`.
- Repository calls for tenant-owned data must always be tenant-scoped.
- Never add cross-tenant reads or writes as convenience shortcuts.
