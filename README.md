# Dependency Firewall

A multi-tenant dependency firewall and proxy for npm and OCI (container) registries. It sits between your developers and upstream registries, evaluating every artifact request against configurable policies before allowing it through.

## Features

- **npm proxy** — intercepts `npm install` and evaluates packages before serving them
- **OCI proxy** — intercepts `docker pull` and evaluates images at the manifest level
- **Policy engine** — YAML-based DSL with CVSS, age, mutable-tag, license, and namespace rules
- **Multi-tenancy** — strict tenant isolation; every request, policy, and decision is scoped to a tenant
- **Enrichment** — vulnerability metadata via [OSV](https://osv.dev) to power CVSS-based policies
- **Audit trail** — every proxy decision is recorded with reasons for later review
- **Control plane API** — REST API for managing tenants, policies, and upstreams

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐
│   npm client │    │ docker client│    │  control plane admin │
└──────┬───────┘    └──────┬───────┘    └──────────┬───────────┘
       │                   │                       │
       ▼                   ▼                       ▼
┌────────────────────────────────────────────────────────────┐
│                     Dependency Firewall                     │
│                                                            │
│  delivery:  /npm/*      /v2/*       /api/v1/*              │
│                ↓           ↓             ↓                 │
│  core:      proxy service + policy evaluator               │
│                ↓                                           │
│  infra:     postgres  valkey  osv.dev  upstream registries │
└────────────────────────────────────────────────────────────┘
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- Go 1.26+ (for local development)

## Running with Docker Compose

The firewall uses [ko](https://ko.build) for fast, minimal container builds that automatically embed build info (git commit, timestamp, etc.).

**Quick start:**

```bash
make up
```

This builds the firewall using `ko` and starts Docker Compose services:

- **Firewall** on `http://localhost:8080`
- **PostgreSQL 16** on `localhost:5432`
- **Valkey 8** on `localhost:6379`

Schema migrations run automatically on startup.

**Other useful commands:**

```bash
make help          # Show all available commands
make down          # Stop services
make logs          # Follow logs
make restart       # Rebuild and restart
make status        # Check service health
```

The Makefile wraps `ko build` with sensible defaults. See the [Makefile](./Makefile) for all available targets.

## Build information

The firewall automatically embeds build information at compile time via `ko`:

```bash
curl http://localhost:8080/healthz | jq .
```

Response includes:

- `commit` — git commit SHA
- `build_time` — build timestamp
- `go_version` — Go runtime version
- `dependencies` — health status of PostgreSQL and Valkey

This information is embedded by `ko` without needing to pass ldflags manually. See `.ko.yaml` for build configuration.

## Running locally

**1. Start dependencies:**

```bash
docker compose up postgres valkey -d
```

**2. Copy and edit config:**

```bash
cp config.yaml.example config.yaml
```

**3. Build and run:**

```bash
go build -o firewall ./cmd/firewall
./firewall
```

Or with environment variables (all config keys are available as `FIREWALL_<KEY>`):

```bash
FIREWALL_DATABASE_DSN="postgres://firewall:firewall@localhost:5432/firewall?sslmode=disable" \
FIREWALL_VALKEY_ADDR="localhost:6379" \
go run ./cmd/firewall
```

## Configuration

| Key | Env override | Default | Description |
| --- | --- | --- | --- |
| `server.port` | `FIREWALL_SERVER_PORT` | `8080` | HTTP listen port |
| `server.read_timeout` | `FIREWALL_SERVER_READ_TIMEOUT` | `5s` | Max time to read request headers/body |
| `server.write_timeout` | `FIREWALL_SERVER_WRITE_TIMEOUT` | `0s` | Max time to write responses; `0s` disables the deadline for proxy streaming |
| `server.idle_timeout` | `FIREWALL_SERVER_IDLE_TIMEOUT` | `120s` | Keep-alive idle timeout |
| `oci_cache.enabled` | `FIREWALL_OCI_CACHE_ENABLED` | `false` | Enable the tenant-aware OCI manifest/blob cache |
| `oci_cache.backend` | `FIREWALL_OCI_CACHE_BACKEND` | `disk` | OCI cache backend (`disk` today; `s3`/`gcs` reserved) |
| `oci_cache.root_dir` | `FIREWALL_OCI_CACHE_ROOT_DIR` | `os.TempDir()/dependency-firewall/oci` | Local disk root for tenant-scoped OCI cache entries |
| `oci_cache.max_bytes` | `FIREWALL_OCI_CACHE_MAX_BYTES` | `0` | Per-tenant disk cache byte limit; `0` disables size-based eviction |
| `oci_cache.max_age` | `FIREWALL_OCI_CACHE_MAX_AGE` | `0s` | Per-tenant max cache age; `0s` disables age-based eviction |
| `oci_cache.max_entries` | `FIREWALL_OCI_CACHE_MAX_ENTRIES` | `0` | Per-tenant object-count limit; `0` disables count-based eviction |
| `database.dsn` | `FIREWALL_DATABASE_DSN` | — | PostgreSQL connection string |
| `valkey.addr` | `FIREWALL_VALKEY_ADDR` | `localhost:6379` | Valkey (Redis-compatible) address |
| `log.level` | `FIREWALL_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `log.format` | `FIREWALL_LOG_FORMAT` | `json` | Log format (`json`, `text`) |

For OCI proxying, keep `server.write_timeout` at `0s` unless you are sure large blob downloads will always complete within your configured deadline.

To enable the first local-disk OCI cache in development:

```yaml
ociCache:
  enabled: true
  backend: disk
  rootDir: "/tmp/dependency-firewall/oci"
  maxBytes: 2147483648
  maxAge: 24h
  maxEntries: 500
```

The OCI cache is **tenant-aware** throughout lookup, on-disk layout, and eviction. Future S3/GCS config surfaces are reserved, but only the disk backend is implemented today.

For deployments that prefer a writable runtime path such as `/tmp/dependency-firewall/oci` or mount a writable volume and point `oci_cache.root_dir` at it.

## Setting up a tenant

Before the proxy can evaluate requests, you need a tenant and an upstream registered via the control plane API.

```bash
# Create a tenant
curl -s -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "my-team"}' | jq .

# Register an npm upstream for that tenant (use the tenant ID from above)
curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "ecosystem": "npm",
    "base_url": "https://registry.npmjs.org",
    "name": "npmjs-public"
  }' | jq .

# Register an OCI upstream for that tenant
curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "ecosystem": "oci",
    "base_url": "https://registry-1.docker.io",
    "name": "docker-hub"
  }' | jq .
```

## Policies

Policies are defined in YAML or JSON and imported via the control plane API. The firewall evaluates **deny-overrides-allow**: any matching `deny` rule blocks the artifact.

YAML and JSON are boundary formats only. Imported policy config is decoded into typed core structs, and unknown config keys or wrong value types are rejected during validation.

Control-plane API payloads and app config are also validated at the boundary with declarative struct validation. Core keeps typed structs plus explicit domain validation for business invariants.

Each policy item must declare an explicit `schema_version`. This version belongs to the policy kind instance (`type` + config shape), not the whole YAML/JSON document. Core compatibility is bound per policy type, so if `minimum_age` changes shape in the future, only `minimum_age` needs a new schema version while unrelated policy types can stay on their existing versions.

### Policy types

| Type                | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `cvss_threshold`    | Deny artifacts with a CVSS score above a threshold                       |
| `minimum_age`       | Deny artifacts published less than N days ago                            |
| `block_mutable_tag` | Deny images pulled by a mutable tag (e.g. `latest`)                      |
| `license`           | Match specific declared licenses using SPDX identifiers                  |
| `license_allowlist` | Deny artifacts whose declared licenses are outside an approved SPDX list |
| `allowlist`         | Record positive matches for trusted packages or namespaces               |
| `namespace_allowlist` | Deny artifacts whose namespace is outside an approved list            |
| `blocklist`         | Explicitly deny packages/namespaces                                      |

### Example policy file

```yaml
# policies/my-team.yaml
tenant_id: "<tenant-id>"
policies:
  - name: block-critical-vulnerabilities
    type: cvss_threshold
    schema_version: 1
    action: deny
    config:
      max_cvss: 7.0
    enabled: true

  - name: block-latest-tag
    type: block_mutable_tag
    schema_version: 1
    action: deny
    config:
      tags:
        - latest
    enabled: true

  - name: block-new-packages
    type: minimum_age
    schema_version: 1
    action: deny
    config:
      min_age_days: 30
    enabled: true

  - name: audit-outdated-packages
    type: maximum_age
    schema_version: 1
    action: deny
    config:
      max_age_days: 730
      dry_run: true
    enabled: true

  - name: allow-approved-licenses
    type: license_allowlist
    schema_version: 1
    action: deny
    config:
      licenses:
        - MIT
        - Apache-2.0
        - BSD-3-Clause
    enabled: true
```

Import it:

```bash
curl -s -X POST http://localhost:8080/api/v1/policies/import \
  -H "X-Tenant-ID: <tenant-id>" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @policies/my-team.yaml | jq .
```

The import endpoint accepts the same policy schema as either **YAML** or **JSON**. Control-plane writes are validated before persistence, and stored policies are validated again before list/get/evaluation so unsupported config keys, missing per-item `schema_version`, or malformed policy data fail safely.

Policy import is an **upsert by policy name within the tenant**:

- importing a new name creates a new policy
- importing an existing name updates that policy in place
- policies omitted from the document are left unchanged
- duplicate policy names inside one document are rejected as invalid input

If stored policy data contains deprecated fields from an older schema revision, the API returns a short migration-style error instead of leaking raw storage or decode details.

### Policy version history and rollback

Each policy keeps the latest **3 retained versions** in `policy_versions`. This supports controlled rollback without keeping unbounded history in the hot control-plane path.

```bash
# List retained versions for a policy
curl -s -H "X-Tenant-ID: <tenant-id>" \
  http://localhost:8080/api/v1/policies/<policy-id>/versions | jq .

# Roll back a policy to a retained version
curl -s -X POST http://localhost:8080/api/v1/policies/<policy-id>/rollback \
  -H "X-Tenant-ID: <tenant-id>" \
  -H "Content-Type: application/json" \
  -d '{"version": 2}' | jq .
```

For license policies, use identifiers from the **SPDX License List**: <https://spdx.org/licenses/>

Use **`license_allowlist`** when you want a strict approved-license policy. It fails closed: if license metadata is missing, the artifact is denied.

For npm, unversioned package metadata requests (`GET /npm/{package}`) are allowed through so the client can resolve a concrete version first. The approved-license check still fails closed on the selected version or tarball request when license metadata is unavailable.

Some older npm package versions do not declare a structured `license` field in registry metadata. In v1, those versions are still denied by `license_allowlist` even if the upstream repository later documents an MIT or other approved license, because enforcement is limited to registry and OSV metadata.

### Discover supported policy types

The control plane exposes a catalog of supported policy types with summaries, help text, **current schema version**, **supported schema versions**, supported actions, and YAML examples:

```bash
curl -s http://localhost:8080/api/v1/policy-types | jq .
```

This endpoint does not require a tenant header because it returns global policy-engine metadata.

## npm proxy example

Point your npm client at the firewall using the `X-Tenant-ID` header or by configuring a custom registry:

```bash
# Fetch package metadata through the firewall
curl -H "X-Tenant-ID: <tenant-id>" \
  http://localhost:8080/npm/express

# Fetch a specific version
curl -H "X-Tenant-ID: <tenant-id>" \
  http://localhost:8080/npm/express/4.18.2

# Scoped package
curl -H "X-Tenant-ID: <tenant-id>" \
  "http://localhost:8080/npm/%40types%2Fnode"
```

**Configure npm to use the firewall** (`.npmrc`):

```ini
registry=http://localhost:8080/npm/
```

When a package is **denied**, npm returns an error like:

```
npm error code E403
npm error 403 Forbidden - GET http://localhost:8080/npm/lodash
npm error 403 Forbidden: policy "block-critical-vulnerabilities" denied: CVSS score 9.8 exceeds threshold 7.0
```

## OCI proxy example

For Docker-compatible OCI traffic, the firewall derives the tenant from a **tenant-specific hostname**.

The primary hosted-registry flow is to pull through that hostname directly:

```bash
# Pull an image manifest through the firewall
curl http://<tenant-id>.localhost:8080/v2/library/nginx/manifests/1.25.3

# Pull by digest (bypasses mutable-tag policy)
curl "http://<tenant-id>.localhost:8080/v2/library/nginx/manifests/sha256:abc123..."

# Hosted-registry Docker UX
docker pull <tenant-id>.localhost:8080/library/nginx:1.25.3
```

`docker login` is not required for this example. The firewall currently supports host-based tenant routing for anonymous pulls, but it does not implement OCI registry authentication.

Use Docker mirror configuration only when you want **transparent local pulls** like `docker pull nginx:1.25.3` to be redirected through the firewall:

**Optional local mirror config** (`/etc/docker/daemon.json`):

```json
{
  "registry-mirrors": ["http://<tenant-id>.localhost:8080"],
  "insecure-registries": ["<tenant-id>.localhost:8080"]
}
```

For local development, make sure `<tenant-id>.localhost` resolves to the firewall host if your environment does not already resolve `*.localhost`.

When a pull is **denied**, Docker returns:

```
Error response from daemon: pull access denied for nginx:latest,
repository does not exist or may require 'docker login': denied:
policy "block-latest-tag" denied: mutable tag "latest" is not allowed
```

## Reviewing decisions

Query recorded proxy decisions via the API:

```bash
curl -H "X-Tenant-ID: <tenant-id>" \
  "http://localhost:8080/api/v1/evaluations?limit=20" | jq .
```

Each decision now includes a `policy_hash` so you can trace which canonical tenant policy set produced that allow or deny result.

## Clearing the decision cache

Clear the cached decisions for one tenant:

```bash
curl -X DELETE http://localhost:8080/api/v1/cache/decisions \
  -H "X-Tenant-ID: <tenant-id>"
```

This clears the **decision cache for that tenant only**. It does not affect other tenants.

## Development

```bash
# Run default test suite (unit + non-tagged tests)
go test ./...

# Run tests with verbose output
go test -v ./...

# Run integration tests (includes PostgreSQL testcontainers tests)
go test ./... -tags integration

# Run everything with race detector (slower)
go test ./... -race -tags integration

# Build binary
go build -o firewall ./cmd/firewall

# Tidy dependencies
go mod tidy
```

PostgreSQL repository integration tests live behind the `integration` build tag, so they are skipped by default unless you pass `-tags integration`.

## Project structure

```
cmd/firewall/          # Entry point — wiring, config, graceful shutdown
internal/
  config/              # Typed config loading, validation, and slog setup
  core/
    domain/            # Types, enums, errors, normalization
    policy/            # Policy config decode, evaluator, and conditions
    port/              # Repository, cache, and service interfaces
    service/           # Proxy orchestration and enrichment
  delivery/
    api/               # Control plane REST API handlers + request validation
    middleware/        # Tenant resolver, logging, recovery
    npm/               # npm protocol handlers
    oci/               # OCI v2 protocol handlers
  infra/
    enrichment/        # Multi-source enrichment composition
    osv/               # OSV vulnerability API client
    postgres/          # PostgreSQL repositories
    upstream/          # npm and OCI upstream registry clients
    valkey/            # Valkey (Redis) decision + metadata caches
  validation/          # Shared boundary-validation helpers
migrations/            # golang-migrate SQL migration files
policies/              # Example policy YAML files
docs/                  # Architecture and design documents
```
