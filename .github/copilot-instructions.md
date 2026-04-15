# Dependency Firewall Copilot Instructions

## Purpose

This repository implements a multi-tenant dependency firewall in Go.

It acts as:
- a proxy for npm and OCI registries
- a policy enforcement point
- a control-plane API
- a multi-tenant service with strict isolation

## Mandatory architecture rules

### Layering

- core must not depend on delivery or infrastructure
- delivery handles HTTP and protocol parsing only
- infrastructure implements persistence, cache, enrichment, and upstream integrations

Allowed dependency directions:
- delivery to core
- infrastructure to core ports and domain
- core to no outer layers

### Core responsibilities

Core is responsible for:
- request normalization
- artifact identity
- policy evaluation
- enrichment orchestration
- decision generation
- tenant-aware business workflows

Core must not:
- access HTTP request or response types
- build SQL
- talk directly to Valkey
- talk directly to PostgreSQL
- call upstream registries directly

### Delivery rules

Delivery layer:
- parses HTTP requests
- converts them to domain models
- calls core services
- renders protocol-specific responses

Delivery must not:
- implement business logic
- evaluate policies
- access PostgreSQL directly
- access Valkey directly

### Infrastructure rules

Infrastructure:
- implements repositories and ports
- handles PostgreSQL, Valkey, OSV, and upstream APIs

Infrastructure must not:
- contain policy logic
- contain HTTP handler logic

## Multi-tenancy rules

- every business operation must have a tenant identifier
- every tenant-owned persisted record must include tenant_id
- every repository query must be scoped by tenant_id
- no cross-tenant reads or writes are allowed

## Proxy rules

### npm
- support metadata and tarball requests
- evaluate policy before serving the artifact
- keep developer-visible errors short and clear

### OCI
- evaluate at manifest level
- resolve tag to digest where possible
- block before serving blobs when deny conditions are met

## Security rules

- do not implement inline artifact scanning
- use OSV and registry metadata only in v1
- cache enrichment results
- fail behavior for enrichment outages must be explicit

## Caching rules

- Valkey is used for decision caching and metadata caching
- always check cache before evaluating
- cache keys must include tenant and normalized artifact identity
- tags should resolve to digests before long-lived cache entries

## Go coding standards

- use context.Context in public functions
- keep interfaces small and close to consumers
- use constructor-based dependency injection
- avoid global mutable state
- keep handlers thin
- keep business logic in services and policy packages

## Developer experience

- do not break npm or docker workflows
- return short human-readable deny messages
- do not expose raw internal errors to users

## Supporting documentation

Read these files when working in this repository:
- docs/architecture.md
- docs/coding-standards.md
- docs/proxy-behavior.md
- docs/policy-engine.md
- docs/persistence.md
