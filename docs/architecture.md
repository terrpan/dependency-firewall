# Architecture

## Goal

Build a multi-tenant dependency firewall that acts as a policy-aware proxy for npm and OCI registries.

## Top-level shape

The system supports three runtime modes in one codebase:

1. Proxy mode
   - registry-compatible proxy endpoints for package managers
   - npm and OCI protocol adapters
   - local request-path evaluation backed by cached tenant bundles

2. Control-plane mode
   - management API for policies, policy rollback/history, upstreams, evaluations, audit events, and cache maintenance
   - intended for UI and automation
   - the React UI consumes generated TypeScript types from the Huma/OpenAPI document
   - Huma is used only on control-plane endpoints where code explicitly uses it
   - serves gRPC bundles for proxies

3. All-in-one mode
   - local-development composition of the same control-plane and proxy boundaries

## System context

```mermaid
flowchart LR
    developer[Developer / CI]
    operator[Operator / UI / Automation]

    developer -->|npm / docker / oci pull| dataplane[Proxy mode]
    operator -->|HTTP API| controlplane[Control plane]

    subgraph firewall[dependency-firewall]
        controlplane --> bundle[delivery/bundlegrpc]
        controlplane --> ingest[delivery/ingestgrpc]
        dataplane --> deliveryProxy[delivery/npm + delivery/oci]
        controlplane --> deliveryAPI[delivery/api]
        bundle --> core
        ingest --> core
        deliveryProxy --> core[core services + policy engine]
        deliveryProxy --> ociProxy[cache-backed OCI proxy path]
        deliveryAPI --> core
        controlplane --> postgres[(PostgreSQL)]
        core --> valkey[(Valkey)]
        ociProxy --> ociCache[(tenant/upstream-aware OCI artifact cache)]
        core --> osv[OSV API]
        core --> scorecard[Scorecard API]
        deliveryProxy --> ingest
        ociProxy --> upstreams[upstream registries]
    end
```

## Internal layers

### Delivery
- HTTP handlers
- npm and OCI protocol parsing
- npm and OCI proxy routes stay on plain `net/http` handlers
- OCI proxy delivery may resolve tenant identity from the request hostname for Docker-compatible traffic
- npm delivery may resolve upstream identity from `/npm/t/{tenant_id}/u/{upstream_id}/...`
- OCI delivery may resolve upstream identity from `u-{upstream_id}.{tenant_id}.{firewall-host}`
- OCI delivery should support both direct registry-hostname usage in hosted deployments and optional Docker mirror usage for transparent local development
- bundle gRPC delivery is control-plane only and serves proxy-ready tenant bundles
- ingest gRPC delivery is control-plane only and persists proxy-emitted decisions and audit events
- bundle and ingest gRPC use mTLS in split control-plane/proxy mode
- control-plane gRPC authorizes proxy certificate identities against tenant IDs before serving bundles or accepting ingest writes
- protocol-specific response rendering
- control-plane request DTO parsing and response DTO rendering
- Huma may be used on control-plane routes for OpenAPI/docs generation and typed request/response modeling
- Huma remains control-plane only
- the current Huma-backed control-plane set includes health, tenants, policy CRUD, policy version history, policy rollback, policy type listing, policy import, evaluation listing, audit-event listing, decision-cache clearing, and upstream CRUD
- boundary request validation
- handlers call core services, not repositories or parser packages

### Core
- request normalization
- policy evaluation
- enrichment orchestration
- tenant-aware decision making
- upstream-aware policy selection
- upstream capability compatibility validation for policy authoring and upstream updates
- control-plane business workflows
- audit event emission and audit-query workflows
- typed domain and policy config models
- shared ports named in protocol-neutral terms where used across ecosystems

### Infrastructure
- PostgreSQL repositories
- encrypted upstream auth secret storage for OCI registry credentials
- Valkey cache implementations
- tenant and upstream-aware OCI artifact cache implementations
- OSV and Scorecard-backed enrichers
- upstream registry clients
- OpenTelemetry exporters and transport instrumentation
- gRPC bundle and ingest client adapters for proxy pulls and write-back

## Layered component view

```mermaid
flowchart TB
    subgraph delivery[delivery]
        npmDelivery[npm registry handler]
        ociDelivery[oci registry handler]
        apiDelivery[control-plane API handlers]
        middleware[tenant + logging + recovery middleware]
    end

    subgraph core[core]
        accessService[AccessService]
        policyService[PolicyService]
        upstreamService[UpstreamService]
        tenantService[TenantService]
        evaluationService[EvaluationService]
        auditService[AuditService]
        enrichmentService[EnrichmentService]
        evaluator[policy evaluator + conditions]
    end

    subgraph infrastructure[infrastructure]
        pgRepos[PostgreSQL repositories]
        bundleRuntime[bundle-backed runtime repos]
        auditSinks[audit sinks]
        valkeyCache[Valkey caches]
        upstreamClients[upstream clients]
        cachedOCI[cache-backed OCI client]
        ociCache[tenant/upstream-aware OCI artifact cache]
        ociStorage[disk backend today / future S3 or GCS]
        enrichers[OSV + npm/Scorecard enrichers]
        grpcClients[gRPC bundle + ingest clients]
    end

    middleware --> npmDelivery
    middleware --> ociDelivery
    middleware --> apiDelivery

    npmDelivery --> accessService
    ociDelivery --> accessService
    apiDelivery --> policyService
    apiDelivery --> upstreamService
    apiDelivery --> tenantService
    apiDelivery --> evaluationService
    apiDelivery --> auditService

    accessService --> enrichmentService
    accessService --> evaluator
    accessService --> bundleRuntime
    accessService --> auditSinks
    accessService --> valkeyCache
    accessService --> upstreamClients
    policyService --> pgRepos
    upstreamService --> pgRepos
    tenantService --> pgRepos
    evaluationService --> pgRepos
    auditService --> pgRepos
    enrichmentService --> valkeyCache
    enrichmentService --> enrichers
    ociDelivery --> cachedOCI
    cachedOCI --> ociCache
    cachedOCI --> upstreamClients
    ociCache --> ociStorage
    bundleRuntime --> grpcClients
    auditSinks --> grpcClients
```

## Dependency direction

- delivery depends on core
- infrastructure depends on core ports and domain
- core depends on neither delivery nor infrastructure

## Split-mode control-plane security

Split mode treats the proxy/control-plane gRPC connection as a tenant data boundary. mTLS authenticates both processes, then the control plane authorizes the proxy certificate identity for the requested tenant before serving bundles or accepting ingest writes. When bundles contain upstream auth secrets, delivery encrypts each secret to the requesting proxy certificate public key; proxy-side bundle infrastructure keeps the envelope in the runtime cache, and OCI upstream infrastructure decrypts it only while constructing outbound registry auth.

```mermaid
flowchart LR
    proxy[Proxy runtime]
    cert[Proxy client certificate identity]
    tls[mTLS transport]
    authz[bundle.tls.authorized_clients]
    bundle[Bundle service]
    ingest[Ingest service]
    tenantA[Tenant A runtime data]
    tenantB[Tenant B runtime data]

    proxy --> cert
    cert --> tls
    tls --> authz
    authz -->|allowed tenant_id| bundle
    authz -->|allowed tenant_id| ingest
    bundle --> tenantA
    ingest --> tenantA
    authz -.->|deny cross-tenant request| tenantB
```

The authorization decision uses the decoded RPC request's `tenant_id`: bundle requests use the requested tenant, and ingest requests use the tenant embedded in the decision or audit payload. Delivery packages own extraction from their wire request types; the shared gRPC infrastructure only enforces the configured identity-to-tenant map. Bundle secret encryption stays in `internal/delivery/bundlegrpc`, while hybrid crypto primitives live in `internal/infra/secrets` and proxy-side decryption lives in `internal/infra/upstream`.

## Control-plane Huma boundary

### In scope

- control-plane API delivery only
- OpenAPI/docs generation at the HTTP boundary
- typed request and response models for the control-plane endpoints that use Huma
- current Huma-backed control-plane endpoints include health, tenants, policy CRUD, policy version history, policy rollback, policy type listing, policy import, evaluation listing, audit-event listing, decision-cache clearing, and upstream CRUD
- per-endpoint Huma coverage remains explicit and human-controlled

### Out of scope

- npm delivery
- OCI delivery
- assuming every control-plane endpoint uses Huma
- assuming every future control-plane endpoint must use Huma automatically
- core service signatures or domain models
- infrastructure repositories, caches, enrichers, or upstream clients

## Observability

- OpenTelemetry tracing is a cross-cutting runtime concern that stays outside core policy logic.
- Delivery boundaries should propagate W3C trace context across HTTP and gRPC.
- Core services may add business spans and span events for evaluation, enrichment, cache, and audit stages.
- Infrastructure clients may instrument PostgreSQL, Valkey, OSV, and upstream registry calls.
- Local development may use Aspire as the OTLP dashboard; this does not change runtime layering or introduce Prometheus requirements.

Huma is a delivery-layer tool. It must not move policy logic, tenant workflows, or persistence concerns out of core and infrastructure. Endpoint coverage stays human-controlled and must reflect explicit code changes, not inferred drift from shared helpers or documentation alone.

## Boundary rules

- delivery must not decode API payloads directly into domain models
- YAML and JSON are boundary formats only; decode them into typed request DTOs and typed policy config structs before core workflows run
- delivery and config packages may use declarative validators for boundary shape checks, but core invariants must stay explicit in typed domain validation
- delivery must not call PostgreSQL or Valkey implementations directly
- delivery must not orchestrate multi-step policy import or evaluation workflows
- delivery must not expose raw PostgreSQL or Valkey errors to API clients; infrastructure errors should be translated to domain-safe errors and logged server-side
- core types must not carry JSON response tags for delivery concerns
- core policy config must use typed structs per policy type, not `map[string]any`
- approved-license policies must keep missing license metadata behavior explicit; `license_allowlist` schema v1 is fail-closed and schema v2 makes unlicensed vs unavailable-metadata handling configurable
- shared ports in core must avoid ecosystem-specific names such as manifest, blob, or tag unless the port is OCI-only
- OCI artifact cache ports may be OCI-specific, but cache ownership, lookup, and lifecycle must remain scoped by `tenant_id` and `upstream_id` across the full app lifecycle

## Data-plane evaluation flow

```mermaid
sequenceDiagram
    participant client as Package manager
    participant delivery as delivery/npm or delivery/oci
    participant access as core.AccessService
    participant dcache as Valkey decision cache
    participant enrich as core.EnrichmentService
    participant bundle as tenant bundle provider
    participant ingest as control-plane proxy ingest service
    participant audit as audit sinks
    participant ocicache as OCI artifact cache
    participant upstream as upstream client

    client->>delivery: proxy request
    delivery->>delivery: parse protocol request + resolve tenant_id + upstream_id
    delivery->>audit: record request_received
    delivery->>access: Evaluate(access request)
    access->>access: normalize artifact identity
    access->>dcache: lookup decision

    alt decision cache hit
        dcache-->>access: cached decision
        access->>audit: record cache hit
    else decision cache miss
        access->>bundle: load tenant bundle
        bundle-->>access: policies + upstreams
        access->>access: filter policies by upstream scope
        access->>access: compute policy-set SHA-256
        opt enabled policies require external metadata
            access->>enrich: load metadata
            enrich-->>access: metadata
            access->>audit: record enrichment result
        end
        access->>access: evaluate policies
        access->>dcache: store decision
        access->>ingest: record decision with policy_hash
        access->>audit: record matched policies + final decision
    end

    alt deny
        access-->>delivery: deny decision
        delivery->>audit: record denied response
        delivery-->>client: protocol-specific denied response
    else allow
        access-->>delivery: allow decision
        delivery->>audit: record allowed response
        delivery->>ocicache: lookup tenant + upstream scoped digest entry
        alt cache hit
            ocicache-->>delivery: cached response stream
        else cache miss
            delivery->>audit: record upstream fetch
            delivery->>upstream: fetch metadata/content
            upstream-->>delivery: upstream response stream
            delivery->>ocicache: opportunistic tenant + upstream scoped cache fill
        end
        delivery-->>client: registry-compatible response
    end
```

## Control-plane flow

```mermaid
sequenceDiagram
    participant operator as UI / automation
    participant api as delivery/api
    participant service as core service
    participant parser as core policy parser
    participant repo as PostgreSQL repository
    participant revisions as PostgreSQL policy revisions
    participant dcache as Valkey decision cache

    operator->>api: POST /api/v1/policies/import
    api->>api: parse content type + tenant_id header
    api->>service: ImportPolicies(tenant_id, body)
    service->>parser: parse + convert YAML or JSON
    parser-->>service: typed domain policies
    service->>repo: create tenant-scoped policies
    repo-->>service: persisted policies
    service->>repo: list tenant policies
    service->>service: compute policy-set SHA-256
    service->>revisions: persist tenant policy revision
    service->>dcache: invalidate tenant decision generation
    service-->>api: import result
    api-->>operator: JSON response DTO
```

## Main runtime flow

1. Request enters delivery layer.
2. Delivery resolves tenant and normalizes the request.
3. Proxy refreshes the tenant bundle on demand when its cached copy is stale.
4. Core evaluates access using the decision cache, effective policies, and enrichment only when a matched enabled policy needs metadata.
5. Proxy persists durable decision and audit records through the control-plane ingestion boundary.
6. If denied, delivery renders a protocol-specific error.
7. If allowed, OCI delivery checks the tenant and upstream-aware artifact cache by digest before going upstream.
8. On OCI cache miss, delivery streams content from upstream while opportunistically filling the cache.

## Audit logging rules

- audit logging uses typed events emitted from delivery and core, not ad hoc text logs
- core decides **when** evaluation audit events are emitted
- infrastructure decides **where** audit events are written
- phase 1 writes audit events to both:
  - structured `slog`
  - control-plane durable persistence backed by PostgreSQL `audit_events`
- request correlation uses a human-readable `X-Request-ID`
- audit sink failure is configurable and defaults to fail-closed
- future external shipping must remain compatible with tenant-scoped routing without changing core service signatures

### Future audit performance

Durable audit writes currently sit on the request path. In split proxy mode, each persisted audit event can require proxy-side fanout, a gRPC ingest call to the control plane, and an individual PostgreSQL insert. This preserves strict fail-closed behavior, but it can add avoidable latency on high-volume OCI pulls where one client operation fans out into manifest and blob requests.

Future optimization should preserve OCI/security semantics while reducing request-path work:

- keep critical audit events synchronous when `audit.failure_mode=fail_closed`, especially request denials, authorization denials, security errors, and durable decision persistence failures
- move informational lifecycle events such as request received, evaluation started, artifact normalized, policies loaded, request allowed, and upstream fetch started to async audit, tracing, or sampled logging
- add a bounded in-process async audit queue for non-critical events, with explicit backpressure behavior instead of unbounded goroutines
- batch proxy-to-control-plane audit ingest and PostgreSQL writes so one pull does not create one gRPC round trip and one insert per audit event
- avoid duplicate hot-path sinks by allowing durable PostgreSQL audit without also writing every audit event to stdout

Any async mode must document its loss/backpressure behavior and should remain opt-in for deployments that require strict audit durability before a request can proceed.

## Deferred goal: graph-backed npm dependency context

This is a **future goal**, not part of the current v1 delivery scope.

### Problem

The current npm flow is artifact-local:

- delivery parses `package@version`
- core evaluates one artifact at a time
- policy does not know whether the artifact is direct, transitive, prod, dev, peer, or optional

That keeps the hot path simple, but it limits how age and governance policies behave for transitive dependencies.

### Recommended future direction

Use a **project-scoped resolved dependency graph** as the source of truth for npm dependency context:

- control plane accepts a lockfile or resolved graph upload per tenant_id + project + environment
- PostgreSQL stores graph revisions, nodes, edges, and activation state
- core derives a normalized dependency context per artifact within the active graph
- delivery/npm stays thin and passes tenant + project + environment + artifact to core
- Valkey caches active graph pointers, normalized artifact context summaries, and decisions

### Future control-plane shape

Recommended future capabilities:

- upload a graph revision for a tenant_id + project + environment
- list graph revisions
- activate a graph revision
- inspect graph-derived artifact context for audit and debugging

### Future policy shape

If this is implemented, policy schema should evolve with a shared selector block rather than package-specific allowlists:

```yaml
- name: block-stale-direct-deps
  type: maximum_age
  schema_version: 2
  action: deny
  priority: 25
  target:
    dependency_scope: [direct]
    dependency_types: [prod, peer]
    on_unknown: warn
  config:
    max_age_days: 730
```

### Cache and persistence impact

PostgreSQL would become the source of truth for graph state:

- `dependency_graph_revisions`
- `dependency_graph_nodes`
- `dependency_graph_edges`
- activation state per tenant_id + project + environment

Valkey would keep hot runtime lookups only:

- active graph pointer
- normalized artifact context summary per graph revision
- decision cache keys that include policy generation + graph revision + context hash

### Performance rules

This design is only acceptable if the expensive work happens **off the request path**:

- parse and normalize the graph at upload or activation time
- precompute a small artifact context summary for runtime use
- never walk dependency edges in PostgreSQL during normal npm tarball or metadata requests
- never recompute direct vs transitive classification per request

### Why deferred

This would improve correctness for transitive dependency policy, but it adds:

- more PostgreSQL storage
- more Valkey memory
- lower decision cache reuse
- more operational complexity around project and environment identity

Current direction:

- keep v1 artifact-local
- keep package-level exceptions small and explicit
- revisit graph-backed evaluation when project-scoped dependency enforcement becomes a higher priority

## Extension guides

- Policy extension guide: `docs/adding-policy-type.md`
- Upstream and ecosystem extension guide: `docs/adding-upstream.md`
