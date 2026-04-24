# Persistence

## PostgreSQL

PostgreSQL is the system of record.

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
- use JSONB only for flexible fields
- `policies.schema_version` and `policy_versions.schema_version` record the policy-item schema used for that row
- `policy_versions` stores retained policy snapshots for rollback and keeps the latest 3 versions per policy
- `tenant_policy_revisions` stores the canonical tenant policy-set hash and generation after every policy mutation
- decisions store the `policy_hash` that was active when the decision was evaluated

## Valkey

Valkey is used for:
- decision cache
- metadata cache

### Cache rules
- keys must include tenant and normalized artifact identity
- long-lived decisions should prefer immutable identities such as digests
- TTL should vary by reason type and freshness of the artifact
