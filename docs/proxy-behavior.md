# Proxy behavior

This document is the canonical protocol and failure-behavior reference for the data plane. Runtime composition belongs in [`architecture.md`](./architecture.md); cache storage belongs in [`persistence.md`](./persistence.md); the current adapter inventory belongs in [`supported-ecosystems.md`](./supported-ecosystems.md).

## Current security boundary

Proxy HTTP endpoints do not authenticate ecosystem clients. Tenant and upstream identity comes from ecosystem-specific routing or test-only headers and is not tied to an authenticated principal. Place the proxy behind a trusted network or authenticated gateway until client authentication is implemented.

Internal proxy-to-control-plane gRPC is a different boundary: split mode requires mTLS and certificate-to-tenant authorization.

## Common evaluation flow

For requests that identify an enforceable artifact version or digest, the proxy:

1. resolves `tenant_id` and upstream;
2. normalizes artifact identity and resolves a mutable tag when needed;
3. loads enabled policies from the cached tenant bundle;
4. obtains ecosystem-specific dependency context when an applicable target requires it;
5. looks up the decision cache;
6. requests only enrichment required by applicable policy types;
7. evaluates every applicable rule;
8. caches and durably records the decision and emits audit events.

A matching deny always wins. Allow policies neither short-circuit evaluation nor override a deny. Evaluation failures fail closed.

## Tenant and upstream routing

### npm

The canonical path is:

```text
/npm/t/{tenant_id}/u/{upstream_id}/...
```

### OCI

Docker-compatible traffic resolves tenant and upstream from a host such as:

```text
u-{upstream_id}.{tenant_id}.{firewall-host}
```

`X-Tenant-ID` remains useful for direct tests and non-Docker clients. It is not an authentication mechanism.

## npm protocol behavior

The proxy supports GET requests for package metadata, versioned metadata, and tarballs, plus npm's bulk-audit POST endpoint.

### Bare packuments

A bare package metadata request does not identify a concrete version. The proxy forwards it without policy enrichment, decision-cache lookup/write, or durable decision persistence.

Before returning a JSON packument, the proxy rewrites each distribution tarball URL to the tenant/upstream-specific firewall path. Because the body changes, it removes `ETag` and recalculates `Content-Length`. This keeps subsequent tarball downloads inside the same firewall routing context.

### Versioned metadata and dist-tags

Versioned metadata follows the common evaluation flow. If a request identifies an npm dist-tag, the proxy resolves it to a concrete version before cache lookup and enrichment. A deny prevents the upstream response from being returned.

Concrete, non-tarball metadata requests can enqueue dependency-graph resolution when required dependency context is missing. The requested package/version becomes the root.

### Tarballs

Tarball paths carry a concrete version and follow policy evaluation, but a dependency-context miss does not enqueue graph work from the tarball path. Graph jobs originate from concrete metadata misses or install-snapshot inference.

### Native bulk audit

The native npm bulk-audit endpoint:

- accepts gzip-encoded bodies;
- limits the decoded request body to 8 MiB;
- returns an empty advisory response instead of forwarding public npm advisory results;
- processes the install snapshot asynchronously with a two-minute timeout;
- infers likely roots from the snapshot and idempotently enqueues them for graph resolution.

Snapshot inference is an additional enqueue source; it is not the only source.

## npm dependency context

Target-aware policies can match direct, transitive, or unknown dependency scope and prod, dev, peer, or optional dependency type.

Lookup order is:

1. Valkey dependency-context cache;
2. control-plane/PostgreSQL context summary;
3. graph enqueue when the request is an eligible concrete metadata request;
4. unknown context while resolution is pending or unavailable.

Context is cached for 30 minutes. Its normalized hash contributes to decision-cache identity so a decision for one graph position is not reused for another graph context.

## OCI protocol surface

The client-facing OCI proxy is GET-only and pull-only:

- `GET /v2/`
- `GET /v2/{name}/manifests/{reference}`
- `GET /v2/{name}/blobs/{digest}`

Push, catalog, tag-list, and client registry-authentication endpoints are not implemented.

### Manifests

Manifest requests run the common policy flow. Mutable tags can be resolved to immutable digests. When allowed, the manifest is streamed from the upstream or optional artifact cache.

Artifact cache writes are staged and promoted only after the upstream stream completes successfully. Partial bodies are discarded. Cache identity includes tenant, upstream, artifact kind, and digest.

### Blobs

Blob requests do not rerun policy evaluation. Before streaming a blob, the proxy queries for an allow decision from the previous hour with the same:

- `tenant_id`
- ecosystem
- namespace
- repository name

The current recent-allow lookup does **not** include `upstream_id`, version, or digest. Therefore a recent manifest allow for one OCI upstream can authorize a blob request for another upstream with the same tenant/repository identity. Treat this as a current multi-upstream constraint, not an intended isolation guarantee.

### Registry authentication

The proxy can authenticate server-side to an OCI upstream with Basic/PAT or static bearer credentials and can follow registry challenge/token flows. Credentials are encrypted at rest and, in split mode, encrypted again to the requesting proxy certificate in tenant bundles.

Client-facing registry authentication is absent. Do not confuse upstream authentication with authentication of Docker/OCI clients to the firewall.

## Cache scope and constraints

| Cache | Scope in current key | Current constraint |
| --- | --- | --- |
| Decision (Valkey) | tenant, generation, dependency-context hash, artifact identity | no `upstream_id` |
| Metadata (Valkey) | tenant, generation, artifact identity | no `upstream_id` |
| Dependency context (Valkey) | tenant, upstream, artifact identity | upstream-scoped |
| Tenant bundle (in process) | tenant | contains upstream-specific records; on-demand refresh |
| OCI artifact (disk) | tenant, upstream, kind, digest | upstream-scoped |

Decision and metadata isolation is tenant-aware but not fully upstream-aware. Tenants with multiple equivalent-ecosystem upstreams must account for possible cross-upstream reuse. Graph-context and OCI artifact caches do include upstream identity.

Policy changes bump the tenant decision-cache generation. The control-plane cache endpoints can separately bump decision and metadata generations.

## Failure behavior

### Policy and enrichment

- policy parsing/evaluation errors fail closed;
- only metadata required by applicable policies is fetched;
- enrichment failure behavior is policy-specific—see [`policy-engine.md`](./policy-engine.md);
- audit behavior follows `audit.failure_mode`.

### Bundle refresh

The split proxy refreshes bundles on demand after `bundle.refresh_interval`. A refresh failure uses an existing last-known-good bundle. If no bundle has ever been cached for the tenant, the request fails.

Last-known-good protects bundle reads only. Uncached decisions still synchronously use ingest for durable decision/audit workflows and may fail during a control-plane outage. Cached decisions may continue when all other required dependencies are available.

### Valkey

Decision, metadata, and dependency-context lookups depend on external Valkey. The bundle cache is not stored in Valkey; it is local process memory.

### OCI artifact cache

Caching is optional. The disk backend is implemented. Selecting `s3` or `gcs` fails startup because those backends are reserved but not implemented.

## Audit and decision persistence

Enforceable requests record decisions and audit events according to configured failure behavior. Bare npm packuments intentionally skip decision persistence because they do not identify a version. OCI blob authorization reads recent manifest decisions rather than creating a second policy decision.

## Possible future work

These are directions, not current guarantees:

- client authentication, scoped tokens, OIDC/CLI login, and registry challenge flows;
- upstream-scoped decision/metadata keys and recent-allow queries;
- stronger OCI digest/path validation and enforced HTTPS for authenticated upstreams;
- S3/GCS artifact cache implementations;
- asynchronous or batched durable audit writes.
