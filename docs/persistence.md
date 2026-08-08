# Persistence

## PostgreSQL

PostgreSQL is the system of record.

- only control-plane and all-in-one runtimes open PostgreSQL connections directly
- dependency-graph-worker mode does not open PostgreSQL; it claims jobs and submits graph results through control-plane gRPC
- proxy mode loads tenant runtime from bundles and sends durable decision or audit writes back through the control-plane ingestion service
- bundle construction is a control-plane workflow backed by PostgreSQL tenant, upstream, and policy state

### Core tables
- tenants
- users
- tenant_memberships
- upstreams
- policies
- policy_versions
- tenant_policy_revisions
- artifacts
- proxy_requests
- evaluations
- evaluation_reasons
- decisions
- audit_events

### Rules
- every tenant-owned table includes tenant_id
- operational tables are indexed by tenant_id and timestamp
- upstreams are unique by `tenant_id + ecosystem + base_url`
- upstreams persist a `capabilities` profile so policy compatibility checks are stable across API, UI, and evaluation workflows
- OCI upstreams may persist server-side auth metadata plus encrypted Basic/PAT or bearer-token secrets; API responses expose only auth status and safe metadata
- upstream auth secrets are encrypted with the configured `secrets.upstream_auth_key`; runtimes fail closed when encrypted auth is needed but the key is unavailable
- when a new capability is added to an ecosystem default set, legacy upstream rows that still match the previous default profile may be backfilled to the new default so existing tenants can use newly introduced compatible policy types
- policies may reference one upstream through `upstream_id`
- `policies.upstream_id` and `policy_versions.upstream_id` are nullable only for legacy tenant-wide rules
- upstream references use foreign keys so upstream deletion is blocked while policies still point at it
- use JSONB only for flexible fields
- `policies.schema_version` and `policy_versions.schema_version` record the policy-item schema used for that row
- `policy_versions` stores retained policy snapshots for rollback and keeps the latest 3 versions per policy
- `tenant_policy_revisions` stores the canonical tenant policy-set hash and generation after every policy mutation
- decisions store the `policy_hash` that was active when the decision was evaluated
- decisions and evaluations may store a compact `dependency_context` JSONB summary when target-aware npm policies participated in evaluation
- `audit_events` stores append-only structured audit records for proxy request, evaluation, decision, and upstream-fetch activity
- audit event payloads use JSONB for flexible structured details, but top-level filtering still relies on tenant_id, event_type, and created_at indexes
- audit queries must stay tenant-scoped and should support correlation lookups by request ID and artifact identity fields
- durable audit persistence is expected to support incident response; sink-failure behavior is configurable and defaults to fail-closed
- proxy-side durable writes arrive through the control-plane ingestion service before they reach `decisions` and `audit_events`
- npm dependency graph roots, nodes, edges, context summaries, and resolver job state are owned by control-plane/all-in-one persistence; split proxy mode only enqueues jobs and looks up context summaries through ingest gRPC, and dependency-graph-worker mode only claims and completes jobs through ingest gRPC

### npm dependency graph tables

- `dependency_graph_roots` stores one graph lifecycle row per `tenant_id + upstream_id + root package + root version`
- `dependency_graph_nodes` stores normalized npm package/version artifacts in a completed graph with minimum depth and observed dependency types
- `dependency_graph_edges` stores parent/child relationships with dependency type `prod`, `dev`, `peer`, or `optional`
- `dependency_context_summaries` stores precomputed per-root context evidence for fast lookup and conflict detection
- graph jobs are idempotent because the root table is unique by tenant, upstream, package, and version
- the control plane claims retryable jobs with row locking on behalf of resolver workers; resolver failures keep evaluation fail-open by leaving request-time context as `unknown`

### Upstream auth secret lifecycle

```mermaid
sequenceDiagram
    participant ui as UI / automation
    participant api as control-plane API
    participant service as UpstreamService
    participant repo as PostgreSQL upstream repository
    participant crypto as AES-GCM secret codec
    participant db as PostgreSQL upstreams
    participant bundle as BundleService
    participant wrap as per-proxy envelope crypto
    participant proxy as Authorized proxy
    participant registry as OCI registry

    ui->>api: create/update OCI upstream auth
    api->>service: validate auth type and ecosystem
    service->>repo: persist upstream auth
    repo->>crypto: encrypt password/PAT/token with secrets.upstream_auth_key
    crypto-->>repo: authenticated ciphertext envelope
    repo->>db: store auth_type, safe metadata, encrypted secret
    api-->>ui: response with auth status only

    proxy->>bundle: GetTenantBundle over authorized mTLS
    bundle->>repo: load tenant upstream metadata without auth secret decrypt
    bundle->>repo: rewrap each configured auth secret
    repo->>crypto: decrypt one stored secret
    repo->>wrap: encrypt to proxy mTLS public key
    wrap-->>bundle: version-2 encrypted envelope
    bundle-->>proxy: bundle for authorized tenant with encrypted auth envelopes
    proxy->>proxy: cache encrypted auth envelopes
    proxy->>proxy: decrypt envelope with proxy private key for outbound auth
    proxy->>registry: upstream request using server-side auth
```

Secret rules:
- plaintext credentials only exist in request memory, repository decrypt/encrypt memory, callback-scoped bundle rewrap memory, outbound proxy request construction, and outbound registry requests
- PostgreSQL stores encrypted secret envelopes, not plaintext credentials
- split-mode proxy bundle caches store per-proxy encrypted auth envelopes, not plaintext credentials
- control-plane API responses and UI details never include password, PAT, or bearer token values
- split-mode bundles include version-2 envelopes encrypted to the requesting proxy certificate public key; usable plaintext auth appears only during proxy-side outbound auth construction

### audit_events

- intended for forensic and incident-response workflows, not just UI history
- one row per structured audit event
- expected payload fields include:
  - `correlation_id`
  - `source`
  - `message`
  - `outcome`
  - `upstream_id`
  - `policy_id`
  - `artifact`
  - `details`
- phase 1 uses both:
  - `event_type` column for exact filtering
  - JSONB payload fields for richer search and future expansion
- indexes should cover:
  - `tenant_id + created_at`
  - `tenant_id + event_type + created_at`
  - `tenant_id + correlation_id + created_at`
  - JSONB payload search

## Valkey

Valkey is used for:
- decision cache
- metadata cache
- npm dependency context cache
- proxy-local caching in split mode
- runtime access through `github.com/valkey-io/valkey-go` while keeping the operator-facing config under `valkey.addr`, `valkey.password`, and `valkey.db`
- OpenTelemetry client spans reporting `db.system=valkey`

### Cache rules
- keys must include tenant and normalized artifact identity
- decision cache keys include dependency context hash when dependency graph context is attached
- long-lived decisions should prefer immutable identities such as digests
- dependency context cache keys include `tenant_id`, `upstream_id`, and normalized npm artifact identity
- TTL should vary by reason type and freshness of the artifact
- OCI artifact cache keys must include `tenant_id`, `upstream_id`, artifact kind, and immutable digest; do not reuse cached OCI content across upstreams even when digests match
