---
applyTo: "cmd/**/*.go,internal/**/*.go,docs/**/*.md"
description: "Repository-specific layering and naming rules for dependency-firewall"
---

# Dependency Firewall Architecture Instructions

Follow these architecture rules when adding or modifying code in this repository. They enforce separation of concerns, consistent naming, and multi-tenant isolation.

Consult `docs/architecture.md` for a system overview. Update it whenever core functionality changes. If it is outdated or missing, contact the architecture owner before proceeding.

## Layer boundaries

### Delivery

- Delivery handlers must call **core services**, not repositories, parser packages, or evaluator packages directly.
- Delivery is responsible for HTTP/protocol parsing and response rendering only.
- Delivery request payloads must decode into delivery-layer request DTOs. Do not decode JSON directly into domain models.
- Boundary formats such as JSON and YAML must be decoded into typed structs before entering core workflows.
- Use declarative validation libraries at delivery/config boundaries only when they eliminate repetitive structural validation code (e.g., required-field checks, format validation) that would otherwise be duplicated across multiple handlers. Keep all business invariants in explicit typed-domain validation.
- Delivery response DTOs belong in delivery. Do not add JSON response tags to core types just to support an HTTP handler.
- Do not return raw PostgreSQL, Valkey, or driver errors to API clients. Translate infrastructure failures to domain-safe errors, log the detailed cause server-side, and return short human-readable API messages.

### Huma (control-plane only)

- Huma is a delivery-layer concern only. Use it in control-plane handlers for OpenAPI/docs generation and typed request/response models at the boundary.
- Huma remains limited to control-plane handlers. The current Huma-backed set includes health, tenants, policy CRUD, policy version history, policy rollback, policy type listing, policy import, evaluation listing, decision-cache clearing, and upstream CRUD.
- Do not introduce Huma into `internal/delivery/npm` or `internal/delivery/oci` unless the architecture docs are explicitly updated for that expansion.
- Do not document or assume a control-plane endpoint is Huma-backed unless that endpoint has been explicitly migrated in code.
- Do not import, reference, or directly use Huma request, response, operation, or OpenAPI types in core or infrastructure packages.

### OCI

- OCI tenant routing for Docker-compatible traffic must use hostname-based resolution at the delivery boundary when the client supports it. Keep `X-Tenant-ID` support only for direct tests or non-Docker clients.
- OCI artifact caching must remain tenant-aware across lookup, writes, cleanup, and future backend extensions. Do not add cross-tenant cache reuse as an implicit shortcut.
- Do not expose filesystem-style abstractions such as `fs.FS` from core for OCI artifact caching. Model cache behavior as a core port and keep storage details in infrastructure.

### Core and infrastructure

- Core services orchestrate workflows across repositories, caches, enrichers, and policy evaluation.
- Infrastructure implements ports. It must not contain policy logic or HTTP handler behavior.

## Shared port naming

- Ports used by more than one ecosystem must use **protocol-neutral** names.
- Avoid OCI-specific names such as `manifest`, `blob`, and `tag` in shared core ports and shared core services.
- Use neutral terms such as `metadata`, `content`, and `reference` in shared abstractions.
- Ecosystem-specific terminology belongs in `internal/delivery/npm`, `internal/delivery/oci`, and ecosystem-specific infrastructure packages.

## Policy engine rules

### Evaluation

- The evaluator is **deny-wins**. Do not document or implement allow rules as bypassing later deny rules unless the evaluator semantics are intentionally changed everywhere.
- Keep policy evaluation pure: no HTTP, no PostgreSQL, no Valkey, no upstream calls inside policy packages.

### Configuration and schema

- Core policy config must use typed config structs per policy type. Do not pass `map[string]any` through core services, repositories, or evaluators.
- Reject unknown policy config fields and wrong types at the decode/validation boundary instead of tolerating them implicitly.
- Policy schema changes must be explicit and versioned. Use per-policy-item `schema_version` plus PostgreSQL data migrations rather than long-lived runtime compatibility for deprecated fields. Schema compatibility must be defined per policy type in core so one policy kind can evolve without forcing unrelated kinds to bump.
- Persisted deprecated or unsupported policy schema data must return short user-facing upgrade errors and must not leak raw storage or decode failures.

### Lifecycle and cache

- Policy rollback must restore from retained policy snapshots, not by reconstructing partial state from current rows.
- Policy create, update, delete, and import workflows must invalidate the tenant decision cache immediately so stale allow/deny decisions are not served after a policy change.
- Policy-set SHA-256 values are for audit and traceability. Do not replace tenant cache generation invalidation with policy hashes on the runtime decision-cache hot path.

### License policies

- For approved-license policies, keep missing license metadata behavior explicit. The current `license_allowlist` policy must fail closed when license metadata is unavailable.
- License policies should use **SPDX identifiers** as their vocabulary. Keep SPDX mapping/normalization at the enrichment or condition edge, not in delivery handlers.

## Naming

- Prefer names that describe business responsibility, not transport mechanics.
- Avoid generic exported type names like `Handler` when a more specific name exists.
- Prefer names like `AccessService`, `PolicyService`, `RegistryHandler`, and `EvaluationService` over ambiguous names.

## Multi-tenancy

- Every tenant-owned workflow must carry `tenant_id`.
- Repository calls for tenant-owned data must always be tenant-scoped.
- Never add cross-tenant reads or writes as convenience shortcuts.

## Handling rule violations

- If a rule violation is detected during code review, the pull request must not be merged until the violation is resolved.
- Rule violations in existing code should be tracked as issues and prioritized for remediation in upcoming work cycles.
- If a rule must be intentionally bypassed due to external constraints, it must be documented with a code comment explaining the reason and linked to a tracking issue. The architecture docs must be updated if the bypass represents a lasting design change.
