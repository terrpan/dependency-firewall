# Persistence and caches

PostgreSQL owns durable control-plane state. External Valkey owns shared decision, metadata, and dependency-context caches. The split proxy also keeps tenant bundles in local process memory, and the optional OCI artifact cache stores immutable bodies on disk.

Only `control-plane` and `all-in-one` modes open PostgreSQL and run migrations. A split proxy accesses durable decisions, audit events, and graph context through control-plane gRPC. The dependency-graph worker receives no PostgreSQL or Valkey credentials.

## PostgreSQL

### Active runtime tables

| Area                     | Tables                                                                                                       | Runtime use                                                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Tenancy                  | `tenants`                                                                                                    | tenant CRUD and bundle identity                                                                                                        |
| Upstreams                | `upstreams`                                                                                                  | upstream configuration, capabilities, encrypted OCI credentials                                                                        |
| Policies                 | `policies`, `policy_versions`, `tenant_policy_revisions`                                                     | active rules, version history/rollback, revision hashes                                                                                |
| Artifacts and evaluation | `artifacts`, `evaluations`, `evaluation_reasons`, `decisions`                                                | normalized identities, evaluation history/reasons, durable decisions                                                                   |
| Audit                    | `audit_events`                                                                                               | configured durable audit sink and list API                                                                                             |
| Dependency graphs        | `dependency_graph_roots`, `dependency_graph_nodes`, `dependency_graph_edges`, `dependency_context_summaries` | job lifecycle, resolved graph, target-aware lookup summaries                                                                           |
| Proxy enrollment         | `proxy_enrollments`, `proxy_installations`, `workload_identities`                                            | digest-only device/user credentials, atomic activation state, Tenant-owned installations, certificate identity metadata and revocation |

`proxy_enrollments` stores HMAC-SHA-256 digests, never plaintext device credentials or user codes. Pending approval, denial, expiry, and one-time consumption are serialized with row locks. Approval atomically creates a pending installation and its Tenant-matched identity; the winning poll activates the installation, returns the certificate once, and clears stored certificate/trust bytes. Human approval and denial store the exact provider-neutral principal issuer and subject as separate nullable pairs, not a provider user row or mutable email. Terminal enrollment states cannot be replayed.

Installation names are unique within a Tenant while pending or active. Revocation marks both the installation and its workload identities. The first authorized gRPC call records `first_connected_at`. Composite foreign keys prevent an installation, identity, or enrollment from crossing the Tenant boundary.

Graph roots are unique by tenant, upstream, package name, and version. Enqueue is therefore idempotent. A completed row is reused rather than refreshed; there is no invalidation/refresh operation. Failed rows become claimable again after their fixed retry time.

### Reserved or unwired schema

The migrations also create:

- `users`
- `tenant_memberships`
- `proxy_requests`

No current repository or runtime workflow reads or writes these tables. Their existence must not be interpreted as implemented user authentication, membership authorization, or proxy-request recording.

## Decision persistence and OCI recent allow

An enforceable evaluation records an artifact and durable decision with reasons/context. Bare npm packuments deliberately do not create decisions.

OCI blob access uses `HasRecentAllow`, which searches for an allow decision during the preceding hour by tenant, ecosystem, namespace, and repository name. The query currently omits `upstream_id`, version, and digest. This can authorize a same-name blob across two OCI upstreams within one tenant and is a documented current constraint.

## Cache inventory

| Cache              | Owner/storage        | Key dimensions                                               | TTL / retention                                                                 | Invalidation                                                          |
| ------------------ | -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Decision           | external Valkey      | tenant, tenant generation, dependency-context hash, artifact | 5 minutes for mutable identity; 1 hour for immutable identity                   | policy mutations/import/rollback and cache API bump tenant generation |
| Metadata           | external Valkey      | tenant, tenant generation, artifact                          | 1 hour for mutable identity; 24 hours for digest identity                       | metadata-cache API bumps tenant generation                            |
| Dependency context | external Valkey      | tenant, upstream, artifact                                   | 30 minutes                                                                      | expiry; repopulated from PostgreSQL summary                           |
| Tenant bundle      | proxy process memory | tenant                                                       | refresh attempted on demand after configured interval; last-known-good retained | process restart or successful refresh replaces entry                  |
| OCI artifact       | disk backend         | tenant, upstream, artifact kind, immutable digest            | configured size/age/count limits; zero means no limit                           | eviction on completed writes according to configured limits           |

Valkey is shared external storage, not “proxy-local.” Bundle cache state is the process-local cache.

### Current upstream-scope limitation

Decision and metadata keys do not include `upstream_id`. They are tenant-scoped, but a tenant with multiple upstreams in the same ecosystem can reuse cache entries across those upstreams when artifact identity otherwise matches.

Dependency-context and OCI artifact cache keys do include upstream identity. The graph context hash in a decision key distinguishes dependency positions but does not add upstream identity by itself.

## Cache behavior

### Decision generation

Decision keys include a per-tenant generation. Tenant-wide invalidation increments `decision-generation:{tenant_id}` instead of scanning and deleting all decision entries. Old entries become unreachable and expire naturally.

Policy create, update, delete, import, and rollback workflows invalidate the tenant decision generation. The policy-set SHA-256 remains an audit/revision identity; it is not used in the hot-path Valkey key.

### Metadata generation

Metadata invalidation similarly increments `metadata-generation:{tenant_id}`. Metadata TTL is selected from artifact mutability rather than a single global value.

### Dependency context

Graph summaries are durable in PostgreSQL. A proxy lookup caches the normalized summary in Valkey for 30 minutes. A normalized `context_hash` participates in decision-cache identity.

### Last-known-good bundle

The proxy fetches a bundle only when a tenant is requested and the cached entry is stale. If refresh fails and an older entry exists, that entry remains usable. If the tenant has no cached entry, the request fails.

This mechanism does not queue durable writes. An uncached evaluation can still fail when decision or audit ingest is unavailable.

### OCI artifact cache

The disk cache creates a staged write and promotes it only when the upstream body finishes successfully. Limits are enforced within tenant/upstream scope after completion. Cross-tenant and cross-upstream reuse is prohibited.

Only `disk` is implemented. `s3` and `gcs` fields reserve a possible future surface; selecting either backend returns a startup error.

## Secret storage

OCI Basic/PAT and static bearer credentials are encrypted in PostgreSQL using the configured base64-encoded 32-byte `secrets.upstream_auth_key`. API responses never return the secret.

For split bundle delivery, the control plane re-encrypts the stored secret to the requesting proxy's mTLS certificate public key. The proxy keeps the encrypted envelope in its bundle cache and decrypts it only while creating outbound registry authentication.

## Transactions and migrations

Migrations are embedded from `migrations/` and applied by PostgreSQL-owning modes at startup. Multi-row workflows that require atomicity should use repository transactions. Do not place SQL in delivery handlers.

## Operational implications

- Back up PostgreSQL for durable configuration, history, decisions, audit events, and dependency graphs.
- Treat Valkey as rebuildable cache state, while recognizing that its outage affects request-path availability.
- Treat local bundle and OCI caches as per-process/per-node state.
- Keep `secrets.upstream_auth_key` stable and protected; losing it makes stored upstream credentials unreadable.
- Keep the independent 32-byte `enrollment.hmac_key` stable and protected while enrollments are outstanding. It is not a proxy bootstrap secret and is never distributed to proxies.
- Do not infer implemented auth features from reserved tables.
