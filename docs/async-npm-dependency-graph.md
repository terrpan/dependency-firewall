# Async NPM Dependency Graph Resolution

## Summary

Add graph-backed npm dependency context without putting expensive resolution on the proxy hot path.

Use PostgreSQL as the durable graph store and Valkey as the hot lookup cache. On graph miss, the proxy continues evaluating with `dependency_context=unknown`, enqueues an async sandbox resolution job, and later requests use the completed graph context. Conflicting graph evidence is classified as `unknown`.

## Key Changes

- Add npm dependency graph domain types:
  - `DependencyGraphRoot`: tenant, upstream, root package, root version, status, graph hash, timestamps, error.
  - `DependencyGraphNode`: normalized npm artifact identity plus depth/context summary.
  - `DependencyGraphEdge`: parent, child, dependency type: `prod`, `dev`, `peer`, `optional`.
  - `DependencyContext`: `scope=direct|transitive|unknown`, dependency types, graph IDs, context hash.
- Add core ports and services:
  - `DependencyGraphRepository` for Postgres-backed graph/job persistence.
  - `DependencyContextCache` for Valkey context lookup.
  - `DependencyGraphQueue` for idempotent async resolve requests.
  - `DependencyContextService` used by `AccessService` after npm version resolution and before policy evaluation.
- Extend policy targeting:

  ```yaml
  target:
    dependency_scope: [direct, transitive]
    dependency_types: [prod, peer, optional]
    on_unknown: warn
  ```

  Default `on_unknown` is `warn`, matching async graph-miss behavior. Policies without `target` keep current behavior.
- Update evaluation and cache behavior:
  - Attach dependency context to `domain.AccessRequest`.
  - Include `context_hash` in decision cache keys so direct/transitive decisions do not reuse artifact-only decisions.
  - Persist dependency context summary on decisions/audit payloads for debugging.
  - Only run graph lookup for concrete npm versions; bare packuments still skip version-sensitive work.
- Discover graph roots from native npm install snapshots:
  - npm reports the complete resolved install set through its built-in audit request (`POST /-/npm/v1/security/advisories/bulk`) after `npm install`/`npm ci` unless `--no-audit` is set; no custom client tooling is required.
  - npm gzips the audit request body (`Content-Encoding: gzip`); the proxy decodes it transparently.
  - The proxy serves this endpoint, captures the snapshot, and answers with an empty advisory set so the npm client proceeds normally. Real upstream advisory data is not forwarded yet; vulnerability enforcement happens through firewall policies.
  - npm sends this request even when the install later fails on a denied tarball, so a denied first install still teaches the system; once the graph resolves, a retried install evaluates with real direct/transitive context.
  - `NPMInstallSnapshotService` infers roots off the hot path via name-level set difference: a snapshot package is a root when no other snapshot package declares its name as a dependency (manifest dependency names are fetched from the upstream with bounded concurrency).
  - Only inferred roots are enqueued as graph-resolution jobs, so one install produces a handful of root jobs instead of one job per tarball; tarball requests never enqueue.
  - If manifest lookups are unreliable and inference degenerates into "everything is a root", the snapshot is skipped instead of fanning out.
- Add sandbox resolver worker:
  - Runs as a separate `dependency-graph-worker` runtime in split deployments.
  - Does not receive PostgreSQL credentials; it claims jobs and submits graph results through authenticated control-plane gRPC.
  - Sends `dependency_graph.tenant_id` in claim/watch requests. Concrete tenant scopes are certificate-authorized and filter claims and wake-up signals; `"*"` selects the global-worker behavior.
  - Subscribes to the `WatchDependencyGraphResolve` server stream for instant wake-up when jobs are enqueued; interval polling remains the fallback for failed-job retries and missed signals.
  - Can still run in-process for local all-in-one/control-plane compatibility when `dependency_graph.run_in_process=true`; in-process workers receive the same wake-up signals through the shared in-memory notifier.
  - Uses bounded concurrency, timeout, retry/backoff, and idempotent job keys.
  - For each root package/version, creates an ephemeral temp workspace with a minimal `package.json`.
  - Runs npm against the configured upstream registry with:

    ```sh
    npm install <pkg>@<version> --package-lock-only --ignore-scripts --no-audit --no-fund --allow-git=none
    ```

  - Reads `package-lock.json` and converts it into normalized nodes, edges, dependency types, and precomputed context summaries.
  - Does not call the firewall npm proxy as its registry to avoid recursive graph-resolution loops.

## Persistence And Runtime Shape

- Add migrations for graph roots, nodes, edges, context summaries, and resolution jobs.
- Keep proxy mode free of direct PostgreSQL access.
- In split mode, proxy uses Valkey for context cache lookups and sends async graph-resolution requests through a control-plane gRPC ingestion-style boundary.
- On a Valkey context-cache miss, the split-mode proxy loads graph context through the `LookupDependencyGraphContext` ingest RPC (tenant-authorized like other ingest calls) and re-populates the Valkey cache; DB-owning runtimes look up Postgres directly.
- Control plane owns durable writes and resolver job lifecycle APIs.
- Dependency graph worker owns npm execution only.
- Valkey stores:
  - active/completed graph context summaries
  - graph miss debounce keys
  - decision cache entries keyed by tenant generation + artifact + context hash

## Important Edge Cases

- Graph missing: evaluate with `unknown`, enqueue once, audit `dependency_graph_miss`.
- Tarball graph miss: evaluate with `unknown`, but do not enqueue a root graph job because tarballs do not identify whether the package is the install root.
- Graph resolving: evaluate with `unknown`, do not enqueue duplicate jobs.
- Resolver failure: store failure status and retry window; continue using `unknown`.
- Conflicting evidence: classify as `unknown`.
- Artifact appears only as non-root in completed graphs: classify as `transitive`.
- Artifact has exact root graph and no conflicting transitive evidence: classify as `direct`.
- No target-aware policies enabled: skip graph lookup/enqueue to avoid unnecessary resolver work.

## Test Plan

- Unit tests for lockfile-to-graph parsing:
  - scoped and unscoped packages
  - prod, peer, optional dependency edges
  - duplicate package/version nodes
  - malformed lockfile and missing version cases
- Core service tests:
  - graph miss enqueues async job and evaluates with unknown context
  - graph hit attaches direct context
  - graph hit attaches transitive context
  - conflicting context becomes unknown
  - decision cache key changes with context hash
  - no target-aware policy skips graph lookup
- Repository/cache tests:
  - idempotent graph job enqueue
  - graph replacement is transactional
  - context summaries are tenant/upstream scoped
  - Valkey miss/hit/error behavior matches existing cache fail-open style
- Delivery/proxy tests:
  - npm concrete metadata/tarball requests preserve current allow/deny behavior
  - bare packuments do not trigger version-sensitive graph lookup
  - audit events include graph miss/hit/resolver-request metadata

## Assumptions

- V1 uses existing PostgreSQL rather than adding Neo4j or another graph database.
- V1 graph scope is `tenant + upstream + root npm package + root version`.
- Graph resolution is async; request-path npm installs are not held open.
- Unknown/conflicting dependency context does not silently become direct or transitive.
- NPM upstream authentication is not currently modeled for npm upstreams, so resolver auth support is deferred until npm upstream auth exists.

## Worker tenant scope

`dependency_graph.tenant_id` defaults to `"*"`, which allows a global worker to claim jobs from every tenant when its certificate is also authorized for `"*"`. Set it to a concrete tenant ID and authorize the worker certificate for that same tenant to restrict claim queries, watch notifications, completion, and failure calls to that tenant.
