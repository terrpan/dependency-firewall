# Supported ecosystems

Dependency Firewall is designed around protocol-neutral artifact identities, upstream capabilities, policy descriptors, and access decisions so additional software package and artifact ecosystems can be added without redefining the product.

The following ecosystem adapters are implemented today:

| Ecosystem | Configuration value | Client surface | Ecosystem-specific capabilities | Current limits |
| --- | --- | --- | --- | --- |
| npm | `npm` | Package metadata, version metadata, tarballs, and native bulk-audit requests | Dist-tag resolution, packument URL rewriting, dependency-context policies, and asynchronous dependency-graph resolution | Upstream authentication is not implemented; bare packuments do not identify an enforceable version |
| OCI Distribution | `oci` | Registry version checks, manifests, and blobs | Tag-to-digest resolution, upstream registry authentication, recent-manifest blob authorization, and optional disk artifact caching | GET/pull only; no client registry authentication; vulnerability, Scorecard, and license enrichment are not implemented |

These values describe current support, not a closed list of package-management systems. Protocol-specific behavior and constraints are documented in [`proxy-behavior.md`](./proxy-behavior.md). Policy compatibility by ecosystem is documented in [`policy-engine.md`](./policy-engine.md). Contributors adding another ecosystem should follow [`adding-upstream.md`](./adding-upstream.md).
