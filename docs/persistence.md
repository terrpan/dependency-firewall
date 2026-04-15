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

## Valkey

Valkey is used for:
- decision cache
- metadata cache

### Cache rules
- keys must include tenant and normalized artifact identity
- long-lived decisions should prefer immutable identities such as digests
- TTL should vary by reason type and freshness of the artifact
