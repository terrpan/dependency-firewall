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
| `telemetry.enabled` | `false` | Enable OpenTelemetry tracing |
| `telemetry.endpoint` | `http://localhost:4317` | OTLP collector endpoint used by the Go runtimes |
| `telemetry.protocol` | `grpc` | OTLP transport protocol: `grpc` or `http/protobuf` |
| `telemetry.sample_ratio` | `1.0` | Parent-based trace sampling ratio for new root spans |
| `telemetry.stdout` | `false` | Emit spans to stdout for troubleshooting; can be used with OTLP or on its own |
| `audit.failure_mode` | `fail_closed` | Audit sink failure behavior |

The Valkey configuration surface is unchanged by the client migration: keep using `valkey.addr`, `valkey.password`, and `valkey.db` to point the runtime at your Valkey endpoint. Under the hood, the Go runtime now uses `github.com/valkey-io/valkey-go`.

If tracing is enabled, Valkey client spans now report `db.system=valkey`.

See [`config.yaml.example`](./config.yaml.example) for a full sample.

In split mode, set `health.proxy_url` if you want the control-plane `/healthz` response to include the proxy's live `/healthz` status instead of the static `separate` marker. The default Compose setup wires this automatically.

## Local tracing with Aspire

The project now emits OpenTelemetry traces across:

- control-plane HTTP
- proxy HTTP
- split-mode gRPC bundle and ingest hops
- PostgreSQL, Valkey, OSV, and upstream registry clients
- core evaluation, enrichment, and audit workflows
- the React UI route navigation and shared API client

### Start Aspire in Docker Compose

The Compose file includes an optional OpenTelemetry Collector in front of the Aspire dashboard behind the `observability` profile:

```bash
FIREWALL_TELEMETRY_ENABLED=true \
docker compose --profile observability up -d postgres valkey control-plane proxy otel-collector aspire-dashboard
```

Open `http://localhost:18888` to inspect traces.

In this local topology:

- Go services export to the collector on `http://localhost:4317`
- the browser exports OTLP/HTTP protobuf to `http://localhost:4318/v1/traces`
- the collector forwards traces to Aspire

If you want spans printed to process stdout while troubleshooting, enable:

```bash
FIREWALL_TELEMETRY_ENABLED=true \
FIREWALL_TELEMETRY_STDOUT=true \
go run ./cmd/firewall
```

You can leave `FIREWALL_TELEMETRY_ENDPOINT` set to mirror spans to both OTLP and stdout, or clear it to use stdout-only tracing.

### All-in-one Go runtime + Vite UI

```bash
docker compose --profile observability up -d postgres valkey otel-collector aspire-dashboard

FIREWALL_TELEMETRY_ENABLED=true \
FIREWALL_TELEMETRY_ENDPOINT=http://localhost:4317 \
go run ./cmd/firewall

cd web
VITE_OTEL_ENABLED=true \
npm run dev
```

When the browser tracing flag is enabled, the UI emits route-navigation spans and injects `traceparent` into shared control-plane API requests so browser and backend traces connect in Aspire. In Vite dev, the browser exporter uses OTLP/HTTP protobuf at `/otlp/v1/traces`, which the dev server proxies to the collector. When the UI runs as its own built service, it can export directly to `http://localhost:4318/v1/traces` through the collector without depending on the control-plane host.

### Split-mode proxy tracing

If you want the standalone proxy service included in the trace view, run the split topology and exercise proxy traffic directly:

```bash
FIREWALL_TELEMETRY_ENABLED=true \
docker compose --profile observability up -d postgres valkey control-plane proxy otel-collector aspire-dashboard

curl http://localhost:8081/npm/t/<tenant-id>/u/<upstream-id>/lodash
curl http://u-<upstream-id>.<tenant-id>.localhost:8081/v2/library/nginx/manifests/1.25.3
```

Those requests emit spans from the **proxy HTTP entrypoint**, the **bundle/ingest gRPC hops**, and the downstream **registry/cache/enrichment** work so the proxy shows up as a first-class service in Aspire.

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
    "capabilities":["publish_time","licenses","vulnerability_lookup","scorecard_lookup"]
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

Enable `scorecard_lookup` on npm upstreams when you want to use the OpenSSF Scorecard policy type.

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
