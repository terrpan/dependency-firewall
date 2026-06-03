# Policy Engine

Policies control which artifacts tenants can install through the proxy. Every policy belongs to a single tenant and is evaluated at request time against the artifact identity plus enriched artifact metadata when the matched enabled policy types require it.

## Evaluation rules

1. Only **enabled** policies are evaluated.
2. Policies with `upstream_id` only evaluate for requests that resolve to that same upstream. Legacy rules without `upstream_id` still apply tenant-wide.
3. Policies run in **priority order** (ascending). Ties break alphabetically by name.
4. **Deny overrides allow** — if any deny policy matches, the outcome is deny regardless of allow matches.
5. The **first** matching deny reason becomes the user-facing error message.
6. All matched reasons (allow and deny) are logged for audit.
7. If **no policies match**, the default outcome is **allow**.
8. Condition lookup or evaluation errors are treated as deny (`evaluation_error`).

## Upstream capability profiles

Policies can be scoped to one upstream with `upstream_id`. When they are, the control plane validates that the upstream ecosystem and capability profile can satisfy the selected policy type.

### Current capability vocabulary

- `publish_time` - supports age-based npm policies
- `licenses` - supports npm license policies
- `vulnerability_lookup` - supports npm CVSS policies
- `scorecard_lookup` - supports npm OpenSSF Scorecard policies
- `manifest_digest_lookup` - supports OCI mutable-tag policies

### Current policy requirements

| Policy type | Supported upstream ecosystems | Required capabilities |
| --- | --- | --- |
| `cvss_threshold` | `npm` | `vulnerability_lookup` |
| `minimum_age` | `npm` | `publish_time` |
| `maximum_age` | `npm` | `publish_time` |
| `scorecard` | `npm` | `scorecard_lookup` |
| `license` | `npm` | `licenses` |
| `license_allowlist` | `npm` | `licenses` |
| `block_mutable_tag` | `oci` | `manifest_digest_lookup` |
| `allowlist` | `npm`, `oci` | none |
| `namespace_allowlist` | `npm`, `oci` | none |
| `blocklist` | `npm`, `oci` | none |

- `GET /api/v1/policy-types` exposes `supported_ecosystems` and `required_capabilities` for UI and automation clients.
- Upstream create and update requests persist a capability profile that the UI reuses when filtering compatible policy types.
- Legacy upstreams that still match an older default capability profile may be upgraded to the current default capability set when new default-backed policy types are introduced.
- Updating an upstream cannot remove capabilities that are still required by scoped policies on that upstream.

## Typed config model

- YAML and JSON are accepted only at the control-plane boundary.
- Imported policy documents are decoded into typed config structs before core validation, persistence, or evaluation.
- Core policy values must not use `map[string]any`; each policy type owns an explicit config type.
- Policy type behavior is defined in compiled policy definition providers in `internal/core/policy/catalog_*.go`, aggregated by `internal/core/policy/catalog.go` (descriptor metadata, condition evaluator, config constructors, action compatibility, and enrichment requirement).
- Unknown config keys and wrong value types are rejected during decode and validation.
- Declarative validators are appropriate for control-plane payload shape checks, but policy semantics still live in explicit core validation.
- Each policy item must declare `schema_version`.
- Stored policies also persist `schema_version` so future breaking config changes can be handled through explicit migrations and upgrade-style API errors.

## Policy schema versioning

Policy schema changes should work like versioned APIs, not silent best-effort compatibility. Schema support is bound to the policy kind implementation in core, not to the document as a whole:

- each policy type owns its own supported schema versions
- current versions are defined in the core policy catalog and used by decode + validation
- `schema_version` is required on every policy item
- unsupported `schema_version` is rejected explicitly at the control-plane boundary
- deprecated stored config should be migrated in PostgreSQL instead of tolerated forever at runtime
- control-plane errors for deprecated or unsupported stored policy data must stay short and human-readable

```yaml
tenant_id: tenant-abc-123
policies:
  - name: block-critical
    type: cvss_threshold
    schema_version: 1
    action: deny
    config:
      max_cvss: 7.0
```

## Policy rollback

- `policy_versions` stores retained policy snapshots for rollback
- the service retains the latest **3** versions per policy
- rollback creates a new current policy version from the chosen retained snapshot
- retained snapshots include the full policy shape needed for rollback: `name`, `type`, `action`, `schema_version`, `config`, `priority`, `enabled`, and `upstream_id`
- rollback is exposed through the control plane:
  - `GET /api/v1/policies/{id}/versions`
  - `POST /api/v1/policies/{id}/rollback`
- `GET /api/v1/policy-types` exposes the current and supported schema versions for each policy type so users can adapt policy files before an upgrade
- the same endpoint also exposes per-type ecosystem and capability requirements for generated clients and the control-plane UI

## Priority

Priority is an integer. Lower values run first. Use it to control evaluation order:

| Priority range | Suggested use |
|----------------|---------------|
| 1–9 | Allow overrides (internal namespaces) |
| 10–19 | Critical security (CVSS threshold, Scorecard) |
| 20–29 | Age-based rules (minimum/maximum age) |
| 30–39 | License and namespace rules |
| 40+ | Catch-all or low-priority rules |

When importing from YAML, set `priority` explicitly. If omitted, policies receive their array index as priority (0, 1, 2…).

## Policy types

### `cvss_threshold`

Denies artifacts with a maximum CVSS vulnerability score at or above the configured threshold. Requires an npm upstream with `vulnerability_lookup`.

```yaml
- name: block-critical-vulnerabilities
  type: cvss_threshold
  action: deny
  priority: 10
  config:
    max_cvss: 7.0
```

- Applies to all packages resolved through the matched upstream; it does not take a package list.
- Skips evaluation (no match) if metadata or CVSS score is unavailable.
- CVSS score comes from the OSV enrichment source.

### `minimum_age`

Denies artifacts published fewer than `min_age_days` days ago. Protects against supply-chain attacks that publish malicious packages and exploit them before the community can audit. Requires an npm upstream with `publish_time`.

```yaml
- name: block-brand-new-packages
  type: minimum_age
  action: deny
  priority: 20
  config:
    min_age_days: 7
```

- Skips evaluation if `PublishedAt` metadata is unavailable.
- Age is calculated as `time.Since(PublishedAt)` in days.
- Supports `exclude_packages` and `dry_run` (see [Common config options](#common-config-options)).

### `maximum_age`

Denies artifacts published more than `max_age_days` days ago. Prevents use of unmaintained or obsolete dependencies. Requires an npm upstream with `publish_time`.

```yaml
- name: block-outdated-packages
  type: maximum_age
  action: deny
  priority: 25
  config:
    max_age_days: 730
    dry_run: true
    exclude_packages:
      - unpipe
      - ee-first
```

- Skips evaluation if `PublishedAt` metadata is unavailable.
- Requires npm metadata enrichment for npm packages.
- Supports `exclude_packages` and `dry_run` (see [Common config options](#common-config-options)).

### `block_mutable_tag`

Denies OCI artifacts that reference a mutable tag (e.g. `latest`). Forces pinning to immutable digests or specific versions. Requires an OCI upstream with `manifest_digest_lookup`.

```yaml
- name: block-latest-tag
  type: block_mutable_tag
  action: deny
  priority: 15
  config:
    tags:
      - latest
      - dev
```

- Only matches when the artifact metadata indicates a mutable tag.
- Intended for OCI registries where tags can be overwritten.

### `scorecard`

Denies npm artifacts when the source repository OpenSSF Scorecard falls below the configured overall minimum score, one or more named check minimums, or both. Requires an npm upstream with `scorecard_lookup`.

```yaml
- name: require-secure-source-repos
  type: scorecard
  schema_version: 1
  action: deny
  priority: 15
  config:
    min_score: 7
    checks:
      binary-artifacts: 10
      branch-protection: 7
    unavailable_scorecard_behavior: skip
```

- `scorecard` must use `action: deny`.
- At least one of `min_score` or `checks` is required.
- `checks` is a map of Scorecard check name to minimum acceptable score.
- Scorecard check names are normalized case-insensitively, so values such as `Branch Protection` and `branch-protection` refer to the same check.
- `min_score` applies to the top-level Scorecard `score` value, while `checks` applies to individual entries in the Scorecard `checks[]` array.
- If both `min_score` and `checks` are configured, both the aggregate score and every named check must pass.
- `unavailable_scorecard_behavior` can be set to:
  - `deny` to fail closed when the package does not resolve to a supported GitHub source repository or the hosted Scorecard data is unavailable
  - `skip` to treat missing repository/Scorecard data as no match for this policy
- Scorecard checks that report a negative score such as `-1` are treated as unavailable data and follow `unavailable_scorecard_behavior`.
- v1 is npm-only. OCI support is deferred until OCI enrichment can derive a trustworthy source repository from image metadata or provenance.

### `license`

Matches artifacts whose declared licenses contain any configured identifier. Use it for targeted match rules such as “deny GPL” or “warn on AGPL”. Requires an npm upstream with `licenses`.

```yaml
- name: block-copyleft-licenses
  type: license
  action: deny
  priority: 30
  config:
    licenses:
      - GPL-3.0-only
      - AGPL-3.0-only
```

- License matching uses identifiers from the **SPDX License List**.
- npm packages are enriched from npm registry metadata for the requested version.
- If license metadata is unavailable, the rule skips (no match).
- In v1, OCI license metadata is not enriched, so this rule currently has effect for npm packages but not OCI images.

### `license_allowlist`

Denies artifacts whose declared licenses are not all contained in the configured approved SPDX list. This is the strict “allow only approved licenses” policy type. Requires an npm upstream with `licenses`.

```yaml
- name: allow-approved-licenses
  type: license_allowlist
  schema_version: 2
  action: deny
  priority: 30
  config:
    licenses:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
    unlicensed_behavior: deny
    unavailable_metadata_behavior: skip
```

- `license_allowlist` must use `action: deny`.
- For npm requests without a concrete version (`GET /npm/{package}`), this rule skips so the client can resolve a version first.
- In schema v1, both missing-license cases fail closed and deny the artifact.
- In schema v2, `unlicensed_behavior` and `unavailable_metadata_behavior` can each be set to:
  - `deny` to fail closed
  - `skip` to treat that case as no match for this policy
- If an artifact declares no licenses, `unlicensed_behavior` decides whether this policy denies or skips.
- If license metadata cannot be determined at all, `unavailable_metadata_behavior` decides whether this policy denies or skips.
- Older npm versions may omit a declared `license` field in registry metadata even when the source repository is MIT-licensed. In v1, those requests are still denied because policy evaluation only uses structured registry metadata. In v2, those requests follow `unlicensed_behavior`.
- If any declared artifact license is outside the configured approved list, this rule denies the artifact.
- In v1, OCI license metadata is not enriched, so this rule effectively fails closed for OCI when evaluated. In v2, OCI behavior for missing license metadata follows `unavailable_metadata_behavior`.

### `allowlist`

Matches artifacts whose namespace is in the configured list. Use with `action: allow` to record a positive policy match for trusted namespaces.

```yaml
- name: allow-internal-packages
  type: allowlist
  action: allow
  priority: 5
  config:
    namespaces:
      - mycompany
      - internal
```

- Namespace is the npm scope (without `@`) or OCI registry/org.
- Allowlist matches do **not** override deny policies. The evaluator remains deny-wins.
- Allowlist is **not** fail-closed. Artifacts outside the list still allow unless another deny policy matches.

### `namespace_allowlist`

Denies artifacts whose namespace is outside the configured approved list. Use with `action: deny` for fail-closed namespace enforcement.

```yaml
- name: allow-only-approved-images
  type: namespace_allowlist
  action: deny
  priority: 10
  config:
    namespaces:
      - library
      - docker
```

- Namespace is the npm scope (without `@`) or OCI registry/org.
- `namespace_allowlist` must use `action: deny`.
- This is the strict namespace policy for cases like allowing only official OCI images from `library`.

### `blocklist`

Matches artifacts whose namespace is in the configured list. Use with `action: deny` to block specific scopes or registries.

```yaml
- name: block-untrusted-scopes
  type: blocklist
  action: deny
  priority: 30
  config:
    namespaces:
      - evil-corp
      - abandoned-org
```

## Common config options

Some policy types support additional config keys beyond their main threshold or namespace fields.

### `dry_run`

Set `dry_run: true` to record a warning without denying the request.

```yaml
config:
  max_age_days: 730
  dry_run: true
```

- Warn mode keeps the overall outcome as allow unless another deny policy matches.
- Warnings are still recorded in evaluation reasons and surfaced to supported clients.
- Only `dry_run` is supported. Older policy files must be updated before import.
- Older stored config formats must be normalized by migration before list/get/evaluation continues.

### `exclude_packages`

Age-based policies support `exclude_packages` for package-specific exemptions.

```yaml
config:
  max_age_days: 730
  exclude_packages:
    - unpipe
    - @scope/stable-lib
```

- `exclude_packages` only skips the matching age condition.
- Other policy types such as CVSS threshold and blocklist still apply.

## Enrichment dependencies

Some policy types depend on metadata from enrichment sources:

| Policy type | Required metadata | Enrichment source |
|---|---|---|
| `cvss_threshold` | `MaxCVSS` | OSV API |
| `minimum_age` | `PublishedAt` | npm registry |
| `maximum_age` | `PublishedAt` | npm registry |
| `block_mutable_tag` | `IsMutableTag` | OCI proxy |
| `scorecard` | `Scorecard` and `SourceRepository` | npm registry + hosted OpenSSF Scorecard API |
| `license` | `Licenses` | npm registry |
| `license_allowlist` | `Licenses` | npm registry |
| `allowlist` | namespace (from artifact identity) | none |
| `namespace_allowlist` | namespace (from artifact identity) | none |
| `blocklist` | namespace (from artifact identity) | none |

The proxy loads the effective policy set before enrichment. If no enabled policy for the matched upstream declares `requiresExternalMetadata`, the request skips metadata-cache and external enrichment work entirely.

Requests that do not identify a single enforceable artifact version or immutable reference also skip version-sensitive enrichment. For npm, `GET /npm/{package}` is a bare packument request, so it bypasses OSV/npm/Scorecard enrichment and decision-cache lookup/write. The later versioned metadata or tarball request is evaluated with the concrete version.

If enrichment fails or metadata is unavailable, age, CVSS, and license conditions **skip** (no match), meaning the artifact is not blocked by that rule. Scorecard behavior follows `unavailable_scorecard_behavior`. Allowlist, namespace allowlist, blocklist, and mutable-tag policies work without external enrichment.

## Deferred goal: dependency-context selectors

This is a **future goal** for npm transitive dependency handling.

Current limitation:

- policy evaluation is artifact-local
- policy does not know whether `package@version` is direct or transitive
- policy does not know prod, dev, peer, or optional relationship

Recommended future direction:

- keep current policy types
- add a shared `target` selector block in a future schema version
- let selectors apply across multiple policy types instead of growing `exclude_packages` lists

Example future shape:

```yaml
- name: warn-stale-transitives
  type: maximum_age
  schema_version: 2
  action: deny
  priority: 26
  target:
    dependency_scope: [transitive]
    dependency_types: [prod, peer, optional]
    on_unknown: warn
  config:
    max_age_days: 3650
    dry_run: true
```

Recommended future defaults:

- direct dependencies use stricter age and governance thresholds
- transitive dependencies use softer age thresholds
- CVSS, blocklist, and other critical deny policies can still stay strict
- unknown dependency context must be explicit, not silently treated as direct

## License source of truth

Use the **SPDX License List** as the authoritative source for license identifiers in policy config:

- SPDX license list: <https://spdx.org/licenses/>
- SPDX license list data: <https://github.com/spdx/license-list-data>

Prefer SPDX identifiers such as `MIT`, `Apache-2.0`, `GPL-3.0-only`, and `BSD-3-Clause` in policy YAML.

## Managing policies

### List supported policy types

Use the control-plane catalog endpoint to inspect supported policy types, help text, and example snippets:

```bash
curl -s http://localhost:8080/api/v1/policy-types | jq .
```

Each item includes:

- `type`
- `summary`
- `description`
- `help`
- `supported_actions`
- `example`

### YAML or JSON import

Import a policy set from a YAML or JSON document. The `X-Tenant-ID` header determines the owning tenant, overriding any `tenant_id` in the document.

```bash
curl -X POST http://localhost:8080/api/v1/policies/import \
  -H "Content-Type: application/x-yaml" \
  -H "X-Tenant-ID: <tenant-id>" \
  --data-binary @policy.yaml
```

JSON imports use the same field names and schema:

```bash
curl -X POST http://localhost:8080/api/v1/policies/import \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  --data-binary @policy.json
```

Document format:

```yaml
tenant_id: "ignored-when-header-is-set"
policies:
  - name: my-rule
    type: cvss_threshold
    action: deny
    priority: 10
    config:
      max_cvss: 7.0
    enabled: true
```

Policy names must be unique per tenant.

Import semantics are **upsert by name** for the policies present in the document:

1. If the tenant does not already have a policy with that name, import creates it.
2. If the tenant already has a policy with that name, import updates the existing policy.
3. Policies not present in the imported document are left unchanged.
4. Duplicate names within the same import document are rejected as invalid.

Policy writes are validated at the API and core-service boundaries, and loaded policies are validated again before list/get/evaluation. Unsupported config keys, wrong value types, and malformed stored policy data are rejected instead of being ignored.

### REST API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/policies` | Create a single policy (JSON body) |
| `GET` | `/api/v1/policies` | List all policies for the tenant |
| `GET` | `/api/v1/policies/{id}` | Get a single policy |
| `PUT` | `/api/v1/policies/{id}` | Update a policy |
| `DELETE` | `/api/v1/policies/{id}` | Delete a policy |
| `POST` | `/api/v1/policies/import` | Import policies from YAML |

All endpoints require the `X-Tenant-ID` header. Policies are scoped to the tenant.

### Example: create a policy via JSON

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "name": "block-outdated",
    "type": "maximum_age",
    "action": "deny",
    "priority": 25,
    "config": {"max_age_days": 365},
    "enabled": true
  }'
```

### Setup scripts

The `examples/npm/setup.sh` and `examples/oci/setup.sh` scripts automate tenant creation, upstream registration, and policy import. Run them after starting the stack:

```bash
make up
./examples/npm/setup.sh
```

### Cache invalidation on policy changes

Policy create, update, delete, and YAML import invalidate the tenant's decision cache immediately.

- New requests do **not** wait for the previous decision TTL to expire.
- Invalidation is tenant-scoped. One tenant's policy change does not affect another tenant's cache.
- The Valkey implementation uses a tenant cache generation, so old decision entries become unreachable as soon as the policy mutation completes.
- The policy-set SHA-256 is **audit metadata**, not the decision cache key.

Operators can also clear the tenant decision cache manually:

```bash
curl -X DELETE http://localhost:8080/api/v1/cache/decisions \
  -H "X-Tenant-ID: <tenant-id>"
```

### Policy-set hash audit trail

Every policy mutation also computes a canonical tenant policy-set SHA-256.

- The hash is recorded in PostgreSQL as a tenant policy revision.
- Every recorded decision stores the `policy_hash` that was active when the evaluation ran.
- The hash is canonicalized from the effective policy set so the same policy state produces the same SHA-256 even if policy order or numeric encoding differed at input time.

## Evaluation flow

```
Request arrives
  → tenant resolved from header or URL path
  → artifact identity normalized
  → if artifact identity is cacheable, decision cache checked (Valkey)
  → if cache HIT → return cached decision
  → load tenant policies from PostgreSQL
  → filter policies by upstream scope
  → compute canonical policy-set SHA-256
  → if enabled policies need metadata and artifact identity is version-specific:
      → metadata cache checked (Valkey)
      → if metadata cache MISS → run enrichers (OSV, npm, Scorecard as needed)
      → cache enriched metadata (30min TTL)
  → evaluate policies in priority order
  → if artifact identity is cacheable, cache decision (5min mutable, 1hr immutable)
  → record decision with policy_hash
  → return allow or deny with reason
```

## Non-goals

- No inline artifact scanning (file contents are not inspected).
- No deep dependency graph resolution (only the requested artifact is evaluated).
- No custom condition plugins (policy types are compiled in).
