# Dependency Firewall

Dependency Firewall is a multi-tenant policy-enforcement proxy and control plane
for software package and artifact traffic.

## How to work in this repository

Before changing behavior, inspect the existing implementation and read the
relevant canonical documentation below. Do not guess current APIs, schemas,
runtime behavior, security controls, or ecosystem capabilities.

When behavior or architecture changes, update the document that owns that
behavior in the same change.

## Documentation map

| When working on                                                             | Read                                                         |
| --------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Architecture, runtime modes, boundaries, control-plane API or internal gRPC | `docs/architecture.md`                                       |
| npm or OCI request/proxy behavior                                           | `docs/proxy-behavior.md`                                     |
| Persistence, transactions, caches or durable state                          | `docs/persistence.md`                                        |
| Policies, evaluation, schemas or enrichment                                 | `docs/policy-engine.md`                                      |
| Adding or changing a policy type                                            | `docs/adding-policy-type.md` and `docs/policy-engine.md`     |
| Adding an ecosystem, upstream capability or protocol adapter                | `docs/adding-upstream.md` and `docs/supported-ecosystems.md` |
| npm dependency graphs                                                       | `docs/async-npm-dependency-graph.md`                         |
| mTLS, internal identity or tenant authorization                             | `docs/mtls.md`                                               |
| Go/API/testing conventions                                                  | `docs/coding-standards.md`                                   |
| Web UI architecture, styling or accessibility                               | `docs/ui-redesign.md`                                        |
| Current ecosystem support and limitations                                   | `docs/supported-ecosystems.md`                               |

Treat these documents as the source of truth for evolving implementation
details. Do not duplicate their inventories in this file.

## Architecture invariants

- Dependency direction is `delivery -> core` and `infrastructure -> core`.
  Core must not depend on delivery or concrete infrastructure.
- Delivery owns protocol boundaries and DTOs; business workflows belong in core.
  Delivery must not issue direct SQL or Valkey operations.
- Infrastructure implements core ports and integrations; it must not contain
  policy semantics or HTTP handler behavior.
- Shared core ports and services use protocol-neutral terminology. Keep
  npm/OCI-specific concepts in ecosystem-specific code.
- Preserve tenant isolation across workflows, persistence and integrations.
  Never introduce cross-tenant reads or writes.
- Tenant routing or a `tenant_id` does not prove caller authorization.

## Policy invariants

When modifying policy behavior, preserve these unless the task explicitly
changes the architecture and corresponding documentation:

- Evaluation is deterministic and deny-wins; an allow never overrides a deny.
- Policy evaluators are pure and perform no infrastructure I/O.
- Core policy configuration is typed and explicitly schema-versioned.

## Repository gotchas

- Every Go source file must contain exactly one `package` declaration. When
  creating a file, use the package established by neighboring files.
- Do not infer implemented authentication or authorization from UI state,
  tenant routing, configuration fields, or reserved database tables.
- Do not document planned capabilities as implemented.

## Verification

Use the smallest relevant checks while iterating, then verify the affected
surface before finishing.

For Go changes:

- `make fmt`
- focused `go test` commands while developing
- `make lint` before committing and testing
- `make test` before completion

For changes that depend on PostgreSQL, Valkey, or integration-tagged behavior:

- `make test-integration`

For web changes:

- `npm --prefix web run lint`
- `npm --prefix web run build`
- relevant Playwright tests

After changing the control-plane API contract or generated policy metadata:

- `npm --prefix web run generate:api`

Never claim a check passed unless it was actually run.
