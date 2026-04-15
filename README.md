# Dependency Firewall

A multi-tenant dependency firewall and proxy for npm and OCI (container) registries. It sits between your developers and upstream registries, evaluating every artifact request against configurable policies before allowing it through.

## Features

- **npm proxy** — intercepts `npm install` and evaluates packages before serving them
- **OCI proxy** — intercepts `docker pull` and evaluates images at the manifest level
- **Policy engine** — YAML-based DSL with four rule types: CVSS threshold, minimum age, mutable tag blocking, and allowlist/blocklist
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
- Go 1.22+ (for local development)

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
./firewall --config config.yaml
```

Or with environment variables (all config keys are available as `FIREWALL_<KEY>`):

```bash
FIREWALL_DATABASE_DSN="postgres://firewall:firewall@localhost:5432/firewall?sslmode=disable" \
FIREWALL_VALKEY_ADDR="localhost:6379" \
go run ./cmd/firewall
```

## Configuration

| Key | Env override | Default | Description |
|-----|-------------|---------|-------------|
| `server.port` | `FIREWALL_SERVER_PORT` | `8080` | HTTP listen port |
| `database.dsn` | `FIREWALL_DATABASE_DSN` | — | PostgreSQL connection string |
| `valkey.addr` | `FIREWALL_VALKEY_ADDR` | `localhost:6379` | Valkey (Redis-compatible) address |
| `log.level` | `FIREWALL_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `log.format` | `FIREWALL_LOG_FORMAT` | `json` | Log format (`json`, `text`) |

## Setting up a tenant

Before the proxy can evaluate requests, you need a tenant and an upstream registered via the control plane API.

```bash
# Create a tenant
curl -s -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "my-team", "slug": "my-team"}' | jq .

# Register an npm upstream for that tenant (use the tenant ID from above)
curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "ecosystem": "npm",
    "url": "https://registry.npmjs.org",
    "name": "npmjs-public"
  }' | jq .

# Register an OCI upstream for that tenant
curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "ecosystem": "oci",
    "url": "https://registry-1.docker.io",
    "name": "docker-hub"
  }' | jq .
```

## Policies

Policies are defined in YAML and imported via the control plane API. The firewall evaluates **deny-overrides-allow**: any matching `deny` rule blocks the artifact.

### Policy types

| Type | Description |
|------|-------------|
| `cvss_threshold` | Deny artifacts with a CVSS score above a threshold |
| `minimum_age` | Deny artifacts published less than N days ago |
| `block_mutable_tag` | Deny images pulled by a mutable tag (e.g. `latest`) |
| `allowlist` | Allow only named packages/namespaces; implicitly deny others |
| `blocklist` | Explicitly deny packages/namespaces |

### Example policy file

```yaml
# policies/my-team.yaml
tenant_id: "<tenant-id>"
policies:
  - name: block-critical-vulnerabilities
    type: cvss_threshold
    action: deny
    config:
      max_cvss: 7.0
    enabled: true

  - name: block-latest-tag
    type: block_mutable_tag
    action: deny
    config:
      tags:
        - latest
    enabled: true

  - name: block-new-packages
    type: minimum_age
    action: deny
    config:
      min_age_days: 30
    enabled: true
```

Import it:

```bash
curl -s -X POST http://localhost:8080/api/v1/policies/import \
  -H "X-Tenant-ID: <tenant-id>" \
  -H "Content-Type: application/x-yaml" \
  --data-binary @policies/my-team.yaml | jq .
```

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

Point Docker at the firewall by configuring it as a [registry mirror](https://docs.docker.com/registry/recipes/mirror/):

```bash
# Pull an image manifest through the firewall
curl -H "X-Tenant-ID: <tenant-id>" \
  http://localhost:8080/v2/library/nginx/manifests/1.25.3

# Pull by digest (bypasses mutable-tag policy)
curl -H "X-Tenant-ID: <tenant-id>" \
  "http://localhost:8080/v2/library/nginx/manifests/sha256:abc123..."
```

**Configure Docker daemon** (`/etc/docker/daemon.json`) to proxy through the firewall:

```json
{
  "registry-mirrors": ["http://localhost:8080"]
}
```

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

## Development

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Build binary
go build -o firewall ./cmd/firewall

# Tidy dependencies
go mod tidy
```

## Project structure

```
cmd/firewall/          # Entry point — wiring, config, graceful shutdown
internal/
  config/              # Viper configuration + slog setup
  core/
    domain/            # Types, enums, errors, normalization
    policy/            # DSL parser, evaluator, condition types
    port/              # Repository, cache, and service interfaces
    service/           # Proxy orchestration and enrichment
  delivery/
    api/               # Control plane REST API handlers
    middleware/         # Tenant resolver, logging, recovery
    npm/               # npm protocol handlers
    oci/               # OCI v2 protocol handlers
  infra/
    osv/               # OSV vulnerability API client
    postgres/          # PostgreSQL repositories
    upstream/          # npm and OCI upstream registry clients
    valkey/            # Valkey (Redis) decision + metadata caches
migrations/            # golang-migrate SQL migration files
policies/              # Example policy YAML files
docs/                  # Architecture and design documents
```
