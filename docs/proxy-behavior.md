# Proxy Behavior

## Delivery boundary

- Huma is control-plane only.
- npm and OCI proxy routes remain plain `net/http` delivery handlers.
- The control-plane API is Huma-backed on top of the same `net/http` `ServeMux`.
- Proxy behavior, policy evaluation, and upstream flow stay unchanged by control-plane API tooling.

## npm

### Supported behaviors
- package metadata requests
- tarball requests

### Expected flow
1. Parse npm request.
2. Resolve package name and version where possible.
3. Normalize to a shared access request.
4. Evaluate policy.
5. If denied, return a short registry-compatible error.
6. If allowed, fetch from upstream and stream back to the client.

## OCI

### Supported behaviors
- v2 manifest requests
- blob requests

### Expected flow
1. Resolve tenant from the OCI hostname when available, with `X-Tenant-ID` retained as a direct-test fallback.
2. Parse repository and reference.
3. Resolve tag to digest when possible.
4. Normalize to a shared access request.
5. Evaluate at manifest level.
6. If denied, return an OCI-compatible denied response.
7. If allowed, consult the tenant-aware OCI cache by immutable digest before going upstream.
8. On cache miss, fetch from upstream, stream back to the client, and opportunistically populate the tenant-aware cache.

## UX rules
- Keep errors short and human-readable.
- Preserve normal npm and docker workflows.
- Do not require a custom CLI wrapper.
- For OCI, document both supported deployment styles explicitly:
  - direct pulls through a tenant-specific registry hostname for hosted environments
  - optional Docker mirror configuration for transparent local development
- OCI artifact caching must stay tenant-aware in lookup, writes, eviction, and future remote backend behavior.
