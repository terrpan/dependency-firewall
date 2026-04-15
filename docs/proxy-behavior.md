# Proxy Behavior

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
1. Parse repository and reference.
2. Resolve tag to digest when possible.
3. Normalize to a shared access request.
4. Evaluate at manifest level.
5. If denied, return an OCI-compatible denied response.
6. If allowed, serve manifest and permit blob retrieval.

## UX rules
- Keep errors short and human-readable.
- Preserve normal npm and docker workflows.
- Do not require a custom CLI wrapper.
