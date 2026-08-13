# Policy engine

Policies decide whether an artifact may pass through the proxy. Each policy belongs to one tenant, may optionally scope itself to an upstream and npm dependency target, and contains a typed, versioned configuration.

## Evaluation semantics

1. Disabled policies are ignored.
2. A policy with `upstream_id` applies only to that upstream; a legacy policy without it is tenant-wide.
3. A policy with `target` applies only when npm dependency context matches its selectors.
4. Policies are ordered by ascending `priority`, then by name.
5. Every applicable policy is evaluated.
6. Any matching deny makes the final outcome deny. An allow match never bypasses a deny.
7. The first matching deny supplies the user-facing reason; all matches are retained for audit.
8. No match defaults to allow.
9. Policy lookup or evaluation errors fail closed as `evaluation_error`.
10. `dry_run: true` and target `on_unknown: warn` record warnings without changing the outcome.

Priority is deterministic ordering, not override precedence. Use lower numbers for reasons that should be surfaced first.

## Policy document

Every item must declare `schema_version`; missing or unsupported versions are rejected.

```yaml
tenant_id: tenant-abc-123
policies:
  - name: block-severe-vulnerabilities
    type: cvss_threshold
    schema_version: 1
    action: deny
    priority: 10
    enabled: true
    upstream_id: optional-upstream-id
    config:
      max_cvss: 7.0
      minimum_severity: high
```

YAML and JSON are decoded at the delivery boundary into per-type config structs. Unknown fields and wrong types are rejected. Core services, repositories, and evaluators do not carry untyped policy maps.

JSON uses the same shape:

```json
{
  "tenant_id": "tenant-abc-123",
  "policies": [
    {
      "name": "block-latest",
      "type": "block_mutable_tag",
      "schema_version": 1,
      "action": "deny",
      "priority": 10,
      "config": {"tags": ["latest"]}
    }
  ]
}
```

When importing through the API, `X-Tenant-ID` determines ownership and overrides document `tenant_id`.

## Dependency targets

The shared `target` block is current functionality and is independent of an individual policy config schema version.

```yaml
- name: warn-on-stale-transitive-peers
  type: maximum_age
  schema_version: 1
  action: deny
  priority: 25
  target:
    dependency_scope: [transitive]
    dependency_types: [peer, optional]
    on_unknown: warn
  config:
    max_age_days: 3650
```

Selectors:

- `dependency_scope`: `direct`, `transitive`, `unknown`
- `dependency_types`: `prod`, `dev`, `peer`, `optional`
- `on_unknown`: `warn` (default), `deny`, or `skip`

If graph context is unknown, `warn` evaluates a matching condition as a warning, `deny` applies the policy normally, and `skip` ignores it. Conflicting graph evidence normalizes to unknown.

Dependency context is requested only for concrete npm artifacts when an enabled policy needs a target. Bare packuments have no concrete version and skip it. See [`async-npm-dependency-graph.md`](./async-npm-dependency-graph.md).

## Supported types

The compiled catalog and `GET /api/v1/policy-types` are authoritative.

| Type | Schemas | Actions | Ecosystem | Required capability | Missing enrichment behavior |
| --- | --- | --- | --- | --- | --- |
| `cvss_threshold` | 1 | deny | npm | `vulnerability_lookup` | skip |
| `minimum_age` | 1 | deny | npm | `publish_time` | skip |
| `maximum_age` | 1 | deny | npm | `publish_time` | skip |
| `block_mutable_tag` | 1 | deny | OCI | `manifest_digest_lookup` | no external enrichment |
| `scorecard` | 1 | deny | npm | `scorecard_lookup` | configured `deny` or `skip` |
| `license` | 1 | allow, deny | npm | `licenses` | skip |
| `license_allowlist` | 1, 2 | deny | npm | `licenses` | v1 denies; v2 configured per case |
| `allowlist` | 1 | allow | npm, OCI | none | no external enrichment |
| `namespace_allowlist` | 1 | deny | npm, OCI | none | no external enrichment |
| `blocklist` | 1 | deny | npm, OCI | none | no external enrichment |

OCI vulnerability, Scorecard, and license enrichment are not implemented. Do not use npm-only metadata policies as OCI enforcement promises.

### Vulnerability threshold

```yaml
- name: block-severe-vulnerabilities
  type: cvss_threshold
  schema_version: 1
  action: deny
  config:
    max_cvss: 7.0
    minimum_severity: high
```

Configure `max_cvss`, `minimum_severity`, or both. The condition matches when either configured threshold is met. Metadata comes from OSV; unavailable vulnerability data skips this rule.

### Minimum and maximum age

```yaml
- name: block-new-packages
  type: minimum_age
  schema_version: 1
  action: deny
  config:
    min_age_days: 7

- name: warn-on-old-packages
  type: maximum_age
  schema_version: 1
  action: deny
  config:
    max_age_days: 730
    dry_run: true
    exclude_packages: [unpipe, "@scope/stable-lib"]
```

Age rules use npm publish time and skip when it is unavailable. `exclude_packages` exempts only that age condition; other deny policies still apply.

### Mutable OCI tags

```yaml
- name: block-mutable-tags
  type: block_mutable_tag
  schema_version: 1
  action: deny
  config:
    tags: [latest, stable, edge]
```

This condition applies to OCI manifest references and does not require an external metadata call.

### OpenSSF Scorecard

```yaml
- name: require-secure-source-repositories
  type: scorecard
  schema_version: 1
  action: deny
  config:
    min_score: 7
    checks:
      binary-artifacts: 10
      branch-protection: 7
    unavailable_scorecard_behavior: skip
```

At least one of `min_score` or `checks` is required. Check names normalize case and punctuation. Negative or absent check scores are unavailable data and follow `unavailable_scorecard_behavior`, which is `deny` or `skip`.

### License match

```yaml
- name: block-copyleft
  type: license
  schema_version: 1
  action: deny
  config:
    licenses: [GPL-3.0-only, AGPL-3.0-only]
```

This matches any configured SPDX identifier. Missing license metadata skips the rule.

### Approved-license enforcement

```yaml
- name: allow-approved-licenses
  type: license_allowlist
  schema_version: 2
  action: deny
  config:
    licenses: [MIT, Apache-2.0, BSD-3-Clause]
    unlicensed_behavior: deny
    unavailable_metadata_behavior: skip
```

Schema 1 denies when the artifact declares no license and when metadata is unavailable. Schema 2 configures those cases separately with `deny` or `skip`. A declared license outside the list always matches the deny rule. Bare npm packuments skip because no version is available.

Use SPDX identifiers from <https://spdx.org/licenses/>.

### Namespace policies

```yaml
- name: record-internal-match
  type: allowlist
  schema_version: 1
  action: allow
  config:
    namespaces: [mycompany, internal]

- name: require-approved-namespaces
  type: namespace_allowlist
  schema_version: 1
  action: deny
  config:
    namespaces: [library, docker]

- name: block-untrusted-namespaces
  type: blocklist
  schema_version: 1
  action: deny
  config:
    namespaces: [evil-corp, abandoned-org]
```

For npm the namespace is the scope without `@`; for OCI it is the organization/repository namespace. `allowlist` records positive matches but does not grant an exemption from either deny rule.

## Enrichment and caches

The proxy loads the effective policy set before enrichment and fetches only metadata required by applicable types. Bare npm packuments skip version-sensitive enrichment and decision caching.

Metadata cache TTLs are:

- mutable identity: 1 hour
- digest identity: 24 hours

Decision TTLs are 5 minutes for mutable identity and 1 hour for immutable identity. Dependency-context hash contributes to the decision key.

Failure behavior is per type, not a global “license skips” rule: `license` skips unavailable data, `license_allowlist` schema 1 fails closed, schema 2 is configurable, and Scorecard follows its explicit unavailable behavior.

## Upstream scoping and compatibility

`upstream_id` is optional for backward compatibility. Without it, a policy is tenant-wide and runtime evaluation may encounter an ecosystem that cannot supply its enrichment. Prefer upstream-scoped policies.

For an upstream-scoped policy, create/update/import validates the catalog's supported ecosystem and required capabilities. Upstream updates cannot remove a capability still required by a scoped policy.

Capability vocabulary:

- `publish_time`
- `licenses`
- `vulnerability_lookup`
- `scorecard_lookup`
- `manifest_digest_lookup`

## Policy lifecycle API

| Operation | Method and path |
| --- | --- |
| List/create | `GET`, `POST /api/v1/policies` |
| Get/update/delete | `GET`, `PUT`, `DELETE /api/v1/policies/{id}` |
| Type catalog | `GET /api/v1/policy-types` |
| Import YAML/JSON | `POST /api/v1/policies/import` |
| Version history | `GET /api/v1/policies/{id}/versions` |
| Rollback | `POST /api/v1/policies/{id}/rollback` |
| Decision-cache clear | `DELETE /api/v1/cache/decisions` |
| Metadata-cache clear | `DELETE /api/v1/cache/metadata` |

Example import:

```bash
curl -sS -X POST http://localhost:8080/api/v1/policies/import \
  -H 'Content-Type: application/x-yaml' \
  -H 'X-Tenant-ID: <tenant-id>' \
  --data-binary @policy.yaml
```

The service retains the latest three snapshots per policy. Rollback creates a new current version from a retained full snapshot, including target, upstream scope, config schema, priority, and enabled state. Policy mutations invalidate the tenant decision-cache generation.

## Evaluation pipeline summary

```text
normalize artifact
  -> resolve mutable tag when needed
  -> load effective bundle policies
  -> attach target dependency context when needed
  -> decision-cache lookup
  -> selective enrichment
  -> evaluate all applicable policies (deny wins)
  -> cache and persist decision
  -> emit audit event
```

OCI blobs are an exception: they do not run this pipeline and instead require a recent allow from a manifest request. See [`proxy-behavior.md`](./proxy-behavior.md).
