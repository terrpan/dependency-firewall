# Policy Engine

Policies control which artifacts tenants can install through the proxy. Every policy belongs to a single tenant and is evaluated at request time against enriched artifact metadata.

## Evaluation rules

1. Only **enabled** policies are evaluated.
2. Policies run in **priority order** (ascending). Ties break alphabetically by name.
3. **Deny overrides allow** — if any deny policy matches, the outcome is deny regardless of allow matches.
4. The **first** matching deny reason becomes the user-facing error message.
5. All matched reasons (allow and deny) are logged for audit.
6. If **no policies match**, the default outcome is **allow**.
7. Condition lookup or evaluation errors are treated as deny (`evaluation_error`).

## Priority

Priority is an integer. Lower values run first. Use it to control evaluation order:

| Priority range | Suggested use |
|----------------|---------------|
| 1–9 | Allow overrides (internal namespaces) |
| 10–19 | Critical security (CVSS threshold) |
| 20–29 | Age-based rules (minimum/maximum age) |
| 30–39 | Blocklists/allowlists |
| 40+ | Catch-all or low-priority rules |

When importing from YAML, set `priority` explicitly. If omitted, policies receive their array index as priority (0, 1, 2…).

## Policy types

### `cvss_threshold`

Denies artifacts with a maximum CVSS vulnerability score above the configured threshold. Requires OSV enrichment.

```yaml
- name: block-critical-vulnerabilities
  type: cvss_threshold
  action: deny
  priority: 10
  config:
    max_cvss: 7.0
```

- Skips evaluation (no match) if metadata or CVSS score is unavailable.
- CVSS score comes from the OSV enrichment source.

### `minimum_age`

Denies artifacts published fewer than `min_age_days` days ago. Protects against supply-chain attacks that publish malicious packages and exploit them before the community can audit.

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

### `maximum_age`

Denies artifacts published more than `max_age_days` days ago. Prevents use of unmaintained or obsolete dependencies.

```yaml
- name: block-outdated-packages
  type: maximum_age
  action: deny
  priority: 25
  config:
    max_age_days: 365
```

- Skips evaluation if `PublishedAt` metadata is unavailable.
- Requires npm metadata enrichment for npm packages.

### `block_mutable_tag`

Denies OCI artifacts that reference a mutable tag (e.g. `latest`). Forces pinning to immutable digests or specific versions.

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

### `allowlist`

Matches artifacts whose namespace is in the configured list. Use with `action: allow` to bypass other deny rules for trusted namespaces.

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
- Give allow rules a lower priority number so they run before deny rules.

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

## Enrichment dependencies

Some policy types depend on metadata from enrichment sources:

| Policy type | Required metadata | Enrichment source |
|---|---|---|
| `cvss_threshold` | `MaxCVSS` | OSV API |
| `minimum_age` | `PublishedAt` | npm registry |
| `maximum_age` | `PublishedAt` | npm registry |
| `block_mutable_tag` | `IsMutableTag` | OCI proxy |
| `allowlist` | namespace (from artifact identity) | none |
| `blocklist` | namespace (from artifact identity) | none |

If enrichment fails or metadata is unavailable, age and CVSS conditions **skip** (no match), meaning the artifact is not blocked by that rule. Allowlist and blocklist conditions work without enrichment.

## Managing policies

### YAML import

Import a policy set from a YAML file. The `X-Tenant-ID` header determines the owning tenant, overriding any `tenant_id` in the file.

```bash
curl -X POST http://localhost:8080/api/v1/policies/import \
  -H "Content-Type: application/x-yaml" \
  -H "X-Tenant-ID: <tenant-id>" \
  --data-binary @policy.yaml
```

YAML file format:

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

Policy names must be unique per tenant. Re-importing the same file will fail if policies already exist.

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

## Evaluation flow

```
Request arrives
  → tenant resolved from header or URL path
  → artifact identity normalized
  → decision cache checked (Valkey)
  → if cache HIT → return cached decision
  → metadata cache checked (Valkey)
  → if metadata cache MISS → run enrichers (OSV, npm)
  → cache enriched metadata (30min TTL)
  → load tenant policies from PostgreSQL
  → evaluate policies in priority order
  → cache decision (5min mutable, 1hr immutable)
  → return allow or deny with reason
```

## Non-goals

- No inline artifact scanning (file contents are not inspected).
- No deep dependency graph resolution (only the requested artifact is evaluated).
- No custom condition plugins (policy types are compiled in).
