# Proxy Behavior

## Delivery boundary

- Huma is control-plane only.
- npm and OCI proxy routes remain plain `net/http` delivery handlers.
- The control plane and proxy can run as separate services.
- The proxy pulls tenant bundles from the control plane over gRPC and evaluates requests locally.
- Tenant identity, status, upstreams, and compiled policy data come from the cached tenant bundle, not PostgreSQL.
- Proxy decision and audit persistence flows through the control-plane ingestion boundary, not direct PostgreSQL repositories.
- All-in-one mode keeps the same bundle and ingestion boundaries but satisfies them in-process for local development.
- New npm and OCI client setup should use explicit upstream-specific routes or hostnames.
- Legacy tenant-only routes and hostnames remain available and resolve to the most recently updated upstream for that tenant and ecosystem.

## npm

### Supported behaviors
- package metadata requests
- tarball requests

### Expected flow
1. Parse npm request.
2. Resolve tenant and upstream from `/npm/t/{tenant_id}/u/{upstream_id}/...` when present, with `X-Tenant-ID` retained for direct tests.
3. Resolve package name and version where possible.
4. Refresh the tenant bundle when the cached copy is stale.
5. Normalize to a shared access request.
6. Evaluate only policies that match the resolved upstream scope plus any legacy tenant-wide rules.
7. Persist the decision and configured durable audit events through the control-plane ingestion path.
8. If denied, return a short registry-compatible error.
9. If allowed, fetch from upstream and stream back to the client.

## OCI

### Supported behaviors
- v2 manifest requests
- blob requests

### Expected flow
1. Resolve tenant and upstream from `u-{upstream_id}.{tenant_id}.{firewall-host}` when present, with `X-Tenant-ID` retained as a direct-test fallback.
2. Parse repository and reference.
3. Refresh the tenant bundle when the cached copy is stale.
4. Resolve tag to digest when possible against the resolved upstream.
5. Normalize to a shared access request.
6. Evaluate only policies that match the resolved upstream scope plus any legacy tenant-wide rules.
7. Persist the decision and configured durable audit events through the control-plane ingestion path.
8. If denied, return an OCI-compatible denied response.
9. If allowed, consult the tenant-aware OCI cache by immutable digest before going upstream.
10. On cache miss, fetch from upstream, stream back to the client, and opportunistically populate the tenant-aware cache.

## UX rules
- Keep errors short and human-readable.
- Preserve normal npm and docker workflows.
- Do not require a custom CLI wrapper.
- Keep policy evaluation local to the proxy request path; do not add per-request control-plane policy RPCs.
- Show package-manager instructions with the explicit upstream route or hostname users must configure.
- For OCI, document both supported deployment styles explicitly:
  - direct pulls through an upstream-specific registry hostname for hosted environments
  - optional Docker mirror configuration for transparent local development
- OCI artifact caching must stay tenant-aware in lookup, writes, eviction, and future remote backend behavior.
