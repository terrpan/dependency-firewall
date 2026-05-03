# Dependency Firewall

Dependency Firewall is a multi-tenant policy-aware proxy for **npm** and **OCI** registries.

It now ships as **one binary**:

| Binary | Modes |
| --- | --- |
| `./cmd/firewall` | `all-in-one`, `control-plane`, `proxy` |

The mode can be selected with:

- config: `runtime.mode`
- env: `FIREWALL_RUNTIME_MODE`
- CLI flag: `-mode`

The control plane exposes gRPC **bundle** and **proxy ingest** services. The proxy pulls tenant bundles from the control plane, evaluates requests locally, and sends durable decision/audit writes back through the control plane. The proxy keeps serving the **last-known-good bundle** when the control plane is temporarily unavailable. In **all-in-one** mode, those boundaries stay in-process and do **not** open separate gRPC listeners.

## Architecture

```text
operators / UI / automation
        |
        v
+-----------------------+   gRPC bundles + ingest   +------------------+
| control plane mode    | <------------------------> | proxy mode       |
| - /api/v1/*           |                            | - /npm/*         |
| - web UI              |                            | - /v2/*          |
| - bundle service      |                            | - local eval     |
| - ingest service      |                            | - local cache    |
+-----------+-----------+                            +---------+--------+
            |                                                  |
            v                                                  v
      PostgreSQL + Valkey                                  Valkey
```

## Prerequisites

- Go 1.26+
- Docker and Docker Compose
- [ko](https://ko.build) for image builds used by the Makefile

## Quick start with Docker Compose

The default Compose topology runs the same image twice:

- control plane on `http://localhost:8080`
- proxy on `http://localhost:8081`
- control-plane gRPC (bundle + ingest) on `localhost:9090`

```bash
make up
```

Useful commands:

```bash
make help
make down
make logs
make logs-control-plane
make logs-proxy
make status
```

## Local development

### All in one

```bash
docker compose up postgres valkey -d
go run ./cmd/firewall
```

This runs:

- control plane API on `http://localhost:8080`
- proxy routes on the same process:
  - `http://localhost:8080/npm/...`
  - `http://localhost:8080/v2/...`
- no separate bundle gRPC listener

### Split modes with one binary

```bash
docker compose up postgres valkey -d

go run ./cmd/firewall -mode=control-plane

FIREWALL_SERVER_PORT=8081 \
FIREWALL_BUNDLE_CONTROL_PLANE_ADDR=127.0.0.1:9090 \
go run ./cmd/firewall -mode=proxy
```

You can also set the mode in `config.yaml`:

```yaml
runtime:
  mode: control-plane
```

## Build

```bash
make build
```

## Configuration

All config keys can be overridden with `FIREWALL_*` environment variables.

| Key | Default | Purpose |
| --- | --- | --- |
| `runtime.mode` | `all-in-one` | Process mode: `all-in-one`, `control-plane`, or `proxy` |
| `server.port` | `8080` | HTTP listen port for the current process |
| `health.proxy_url` | `""` | Optional proxy `/healthz` URL for control-plane split-mode health checks |
| `bundle.listen_addr` | `:9090` | gRPC bundle listen address for control-plane mode |
| `bundle.control_plane_addr` | `127.0.0.1:9090` | gRPC address the proxy uses for bundle and ingest RPCs |
| `bundle.refresh_interval` | `30s` | On-demand bundle refresh interval in proxy mode |
| `database.dsn` | `postgres://localhost:5432/firewall?sslmode=disable` | PostgreSQL connection string for `all-in-one` and `control-plane` modes |
| `valkey.addr` | `localhost:6379` | Valkey address |
| `oci_cache.enabled` | `false` | Enable tenant-aware OCI artifact caching |
| `audit.failure_mode` | `fail_closed` | Audit sink failure behavior |

See [`config.yaml.example`](./config.yaml.example) for a full sample.

In split mode, set `health.proxy_url` if you want the control-plane `/healthz` response to include the proxy's live `/healthz` status instead of the static `separate` marker. The default Compose setup wires this automatically.

## Create a tenant and upstreams

All control-plane examples below use `http://localhost:8080`.

```bash
curl -s -X POST http://localhost:8080/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"name":"my-team"}' | jq .

curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "name":"npmjs-public",
    "ecosystem":"npm",
    "base_url":"https://registry.npmjs.org",
    "capabilities":["publish_time","licenses","vulnerability_lookup"]
  }' | jq .

curl -s -X POST http://localhost:8080/api/v1/upstreams \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: <tenant-id>" \
  -d '{
    "name":"docker-hub",
    "ecosystem":"oci",
    "base_url":"https://registry-1.docker.io",
    "capabilities":["manifest_digest_lookup"]
  }' | jq .
```

## npm example

When running split modes, proxy examples use `http://localhost:8081`.

```bash
curl http://localhost:8081/npm/t/<tenant-id>/u/<upstream-id>/lodash

npm config set registry http://localhost:8081/npm/t/<tenant-id>/u/<upstream-id>/

npm install lodash@4.17.21
```

## OCI example

```bash
curl http://u-<upstream-id>.<tenant-id>.localhost:8081/v2/library/nginx/manifests/1.25.3

docker pull u-<upstream-id>.<tenant-id>.localhost:8081/library/nginx:1.25.3
```

## Tests

```bash
make test
make test-integration
```

## Repository layout

```text
cmd/firewall/        single entrypoint with runtime mode selection
internal/bootstrap/  runtime composition for each mode
internal/core/       domain, ports, services, policy engine
internal/delivery/   HTTP and gRPC delivery adapters
internal/infra/      PostgreSQL, Valkey, upstream, enrichment, bundle adapters
web/                 control-plane UI
```
