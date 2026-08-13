# Dependency Firewall

Dependency Firewall is a multi-tenant, policy-aware proxy for software packages and artifacts. One Go binary provides four runtime modes; a separately deployed React/Vite SPA provides the operator console. See [supported ecosystems](./docs/supported-ecosystems.md) for the currently implemented client protocols and capabilities.

> [!WARNING]
> Public management and proxy HTTP routes do not currently validate bearer tokens or enforce RBAC. Tenant selection from headers, paths, or hostnames is routing context, not authenticated user authorization. Use trusted network boundaries until HTTP authentication is implemented. Split-mode internal gRPC is protected separately with mTLS and certificate-to-tenant authorization.

## Runtime modes

Select a mode with `runtime.mode`, `FIREWALL_RUNTIME_MODE`, or `-mode`.

| Mode | HTTP | gRPC | PostgreSQL | Valkey | External resolver tools |
| --- | --- | --- | --- | --- | --- |
| `control-plane` | Management API, OpenAPI, API docs | Bundle and ingest server | Required; runs migrations | Required | Node.js/npm only when `dependency_graph.run_in_process=true` |
| `proxy` | Supported ecosystem routes and `/healthz` | Bundle and ingest client | No | Required | None |
| `all-in-one` | Management and proxy routes on one mux | Local adapters; no listener | Required; runs migrations | Required | Node.js/npm only when `dependency_graph.run_in_process=true` |
| `dependency-graph-worker` | None | Ingest client | No | No | Node.js/npm |

External resolver tools are executables used by background dependency-graph resolution; this column does not describe which ecosystem protocols a mode can proxy. The current dependency-graph resolver uses Node.js/npm.

`dependency_graph.run_in_process` defaults to `false`. Consequently, the default all-in-one process can enqueue dependency-graph jobs but cannot resolve them unless a separate worker runs or in-process resolution is explicitly enabled.

## Architecture

```text
browser                 operators / automation       ecosystem clients
   |                              |                           |
   v                              v                           v
+-----------+             +---------------+   mTLS    +-------------+
| React/Vite| ----------> | control plane | <-------> | proxy       |
| SPA       | HTTP API    | API + gRPC    |           | local eval  |
+-----------+             +-------+-------+           +------+------+
                                  |                          |
                         PostgreSQL + Valkey               Valkey
                                  ^
                                  | mTLS ingest
                         +--------+---------+
                         | dependency graph |
                         | worker + npm     |
                         +------------------+
```

The Go runtime does not serve `web/dist`, and the default Compose topology does not deploy the SPA. Serve the built UI independently and configure it to call the control-plane API.

In split mode the proxy fetches tenant bundles, evaluates requests locally, and sends durable decisions and audit events back through the ingest service. Bundle refresh is on demand. A cached last-known-good bundle protects bundle reads after a refresh failure, but it does not make the proxy independent of the control plane: uncached evaluations can still fail if synchronous decision or audit ingestion is unavailable.

See:

- [Architecture](./docs/architecture.md)
- [Supported ecosystems](./docs/supported-ecosystems.md)
- [Proxy behavior](./docs/proxy-behavior.md)
- [Policy engine](./docs/policy-engine.md)
- [Persistence and caches](./docs/persistence.md)
- [mTLS](./docs/mtls.md)
- [Dependency graphs](./docs/async-npm-dependency-graph.md)
- [UI architecture](./docs/ui-redesign.md)

## Prerequisites

- Go 1.26+
- Docker and Docker Compose
- [ko](https://ko.build) for Makefile image builds
- Node/npm only for the dependency-graph worker and UI development

## Quick start

The default Compose topology runs separate control-plane, proxy, and dependency-graph-worker services. `make up` creates local test certificates under `examples/mtls/certs` and starts the mTLS topology.

```bash
make up
```

Services:

- control-plane HTTP: `http://localhost:8080`
- proxy HTTP: `http://localhost:8081`
- bundle and ingest gRPC: `localhost:9090`

Useful commands:

```bash
make help
make status
make logs
make down
```

Use [`examples/mtls`](./examples/mtls/README.md) for runnable split-mode configuration. Standalone proxy and worker modes cannot start with the insecure defaults because both require mTLS. A control plane may use `bundle.tls.allow_insecure_control_plane=true` only as an explicit local-development exception.

## Local all-in-one development

```bash
docker compose up -d postgres valkey
go run ./cmd/firewall
```

This starts the management API and proxy routes on `http://localhost:8080` without a gRPC listener. To resolve queued dependency graphs in that process, set:

```yaml
dependency_graph:
  run_in_process: true
```

## Operator UI

The UI is a separate React/Vite application.

```bash
cd web
npm ci
npm run dev
```

For a production asset build:

```bash
cd web
npm ci
npm run build
```

Serve `web/dist` from a static host and route API requests to the control plane. See [`web/README.md`](./web/README.md) for environment and test details. Current pages cover Dashboard, Tenants, Upstreams, Policies, Evaluations, and Dependency Graphs. Audit events are available through the API but do not yet have a UI route.

## Configuration

All keys can be overridden with `FIREWALL_*` environment variables. For example, `bundle.control_plane_addr` maps to `FIREWALL_BUNDLE_CONTROL_PLANE_ADDR`.

[`config.yaml.example`](./config.yaml.example) is the complete annotated configuration surface. Important mode ownership rules are:

- PostgreSQL: `all-in-one` and `control-plane` only.
- Valkey: `all-in-one`, `control-plane`, and `proxy`; not the worker.
- `bundle.listen_addr` and `bundle.tls.authorized_clients`: control plane only.
- `bundle.control_plane_addr`: proxy and worker; retained for local composition.
- `dependency_graph.run_in_process`: all-in-one/control-plane compatibility only.
- Node/npm: worker, or a process explicitly running the graph worker in-process.
- OCI artifact cache: proxy path; disk is the only implemented backend. `s3` and `gcs` are reserved configuration and fail startup if selected.

Authenticated OCI upstream credentials are encrypted in PostgreSQL with `secrets.upstream_auth_key` and never returned by the API. In split mode the control plane additionally encrypts each secret to the requesting proxy certificate before bundle delivery.

## API discovery

The control plane publishes:

- OpenAPI: `/api/openapi`
- interactive API docs: `/api/docs`
- management API: `/api/v1/*`

These endpoints are currently unauthenticated. Registered operations in the generated OpenAPI document are authoritative.

Create a tenant and upstream:

```bash
curl -sS -X POST http://localhost:8080/api/v1/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-team"}'

curl -sS -X POST http://localhost:8080/api/v1/upstreams \
  -H 'Content-Type: application/json' \
  -H 'X-Tenant-ID: <tenant-id>' \
  -d '{
    "name":"npmjs-public",
    "ecosystem":"npm",
    "base_url":"https://registry.npmjs.org",
    "capabilities":["publish_time","licenses","vulnerability_lookup","scorecard_lookup"]
  }'
```

## Proxy examples

npm:

```bash
npm config set registry http://localhost:8081/npm/t/<tenant-id>/u/<upstream-id>/
npm install lodash@4.17.21
```

OCI manifest request:

```bash
curl -H 'Host: u-<upstream-id>.<tenant-id>.localhost' \
  http://localhost:8081/v2/library/nginx/manifests/1.25.3
```

The current OCI client surface is GET-only and pull-only. Client registry authentication is not implemented; upstream Basic/PAT and static bearer credentials are supported server-side.

## Telemetry

All Go modes can emit OpenTelemetry traces for HTTP, gRPC, PostgreSQL, Valkey, enrichers, and upstream clients. The browser can emit navigation spans and propagate `traceparent` through the shared API client. Use the Compose `observability` profile to run the collector and Aspire dashboard:

```bash
FIREWALL_TELEMETRY_ENABLED=true \
docker compose --profile observability up -d \
  postgres valkey control-plane proxy dependency-graph-worker \
  otel-collector aspire-dashboard
```

Open `http://localhost:18888`. SQL statement/span-name handling is controlled by `telemetry.sql_tracing` in the sample configuration.

## Tests

```bash
go test ./...

cd web
npm run lint
npm run build
npm run test:e2e
```

## Repository layout

```text
cmd/firewall/        one entrypoint with runtime mode selection
internal/bootstrap/  runtime composition
internal/core/       domain, ports, services, and policy engine
internal/delivery/   HTTP and gRPC adapters
internal/infra/      PostgreSQL, Valkey, upstream, cache, and telemetry adapters
migrations/          PostgreSQL schema migrations
web/                 separately served React/Vite control-plane client
```

## Extension guides

- [Add a policy type](./docs/adding-policy-type.md)
- [Add an upstream or ecosystem](./docs/adding-upstream.md)
- [Coding standards](./docs/coding-standards.md)
