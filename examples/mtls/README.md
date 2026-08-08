# Split Mode mTLS Example

This example runs `dependency-firewall` as separate processes:

- `control-plane`: HTTP control-plane API on `localhost:8080` and mTLS bundle/ingest gRPC on `localhost:9090`
- `proxy`: package proxy on `localhost:8081`, connected to the control plane over mTLS
- `dependency-graph-worker`: isolated npm dependency graph resolver, connected to the control plane over mTLS

The example is for local development only. It creates self-signed test certificates and uses a test upstream secret key in `control-plane.yaml`.

## Files

- `control-plane.yaml`: mounted only into the control-plane container
- `proxy.yaml`: mounted only into the proxy container
- `generate-certs.sh`: creates a local CA, a control-plane server cert, a proxy client cert, and a dependency graph worker client cert
- `seed.sh`: creates a tenant through the control-plane API and adds an OCI upstream for that tenant
- `docker-compose.yml`: runs the split control-plane/proxy/worker topology plus PostgreSQL and Valkey

The Compose file mounts only the certificate files each process needs:

- control plane: CA bundle plus control-plane server certificate/key
- proxy: CA bundle plus proxy client certificate/key
- dependency graph worker: CA bundle plus worker client certificate/key

The proxy and worker containers do not receive the control-plane private key. The worker container does not receive PostgreSQL credentials.

The example proxy uses an ephemeral disk cache under `/tmp/dependency-firewall/oci-cache` inside the container. For production, mount a cache directory that is writable by the application user and keep cache keys tenant/upstream scoped.

The proxy client certificate has this DNS SAN identity:

```text
proxy-a.firewall.local
```

For local convenience, the control-plane config authorizes that identity for all tenants with `tenant_ids: ["*"]`. Production configs should list explicit tenant IDs instead.

```yaml
bundle:
  tls:
    authorized_clients:
      - identity: "proxy-a.firewall.local"
        tenant_ids:
          - "*"
      - identity: "dependency-graph-worker.firewall.local"
        tenant_ids:
          - "*"
```

## Run

From the repository root, build the local image first:

```bash
make build
make build-worker
```

Generate test certificates and start the split deployment:

```bash
cd examples/mtls
./generate-certs.sh
docker compose up -d
```

To include telemetry and Aspire:

```bash
FIREWALL_TELEMETRY_ENABLED=true docker compose --profile observability up -d
```

Open `http://localhost:18888` to inspect traces.

Environment variables override values in `control-plane.yaml`, `proxy.yaml`, and the worker service environment. If the stack is already running and you change `FIREWALL_TELEMETRY_ENABLED`, recreate the app containers so Docker Compose applies the new environment:

```bash
FIREWALL_TELEMETRY_ENABLED=true \
docker compose --profile observability up -d --force-recreate control-plane proxy dependency-graph-worker
```

If local Postgres or Valkey already uses the default host ports, override only the host bindings:

```bash
FIREWALL_POSTGRES_PORT=15432 \
FIREWALL_VALKEY_PORT=16379 \
FIREWALL_CONTROL_PLANE_PORT=18080 \
FIREWALL_PROXY_PORT=18081 \
FIREWALL_BUNDLE_PORT=19090 \
FIREWALL_TELEMETRY_ENABLED=true \
docker compose --profile observability up -d
```

Check health:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8081/healthz
```

Seed the tenant and OCI upstream:

```bash
./seed.sh
```

If you changed the control-plane host port, pass that URL to the seed script:

```bash
FIREWALL_CONTROL_PLANE_URL=http://localhost:18080 ./seed.sh
```

The seed script prints the generated tenant ID and registers Docker Hub as that tenant's OCI upstream. Use that tenant ID in the proxy request examples below.

Then request through the proxy. For direct local tests, `X-Tenant-ID` must be only the raw tenant ID:

```bash
curl -H "X-Tenant-ID: <tenant-id-from-seed-output>" \
  http://localhost:8081/v2/library/nginx/manifests/latest
```

Do not put `.localhost` in `X-Tenant-ID`; that suffix belongs only in the `Host` header form.

You can also use a tenant host name instead of the direct-test header:

```bash
curl -H "Host: <tenant-id-from-seed-output>.localhost" \
  http://localhost:8081/v2/library/nginx/manifests/latest
```

## What This Proves

- The proxy uses its client certificate from `proxy.yaml`.
- The control plane verifies that certificate against `ca.pem`.
- The control plane extracts `proxy-a.firewall.local` from the proxy certificate.
- The control plane authorizes the proxy identity before serving bundle or ingest RPCs.
- The proxy can serve requests for that tenant without mounting the control-plane private key.
- The dependency graph worker claims resolver jobs over mTLS without mounting database credentials.

## Negative Check

To test tenant-specific denial, replace `tenant_ids: ["*"]` in `control-plane.yaml` with the tenant ID printed by `seed.sh`, restart the control plane, then request another tenant ID. The proxy should fail to fetch that other tenant's bundle from the control plane.

## Cleanup

```bash
docker compose down -v
rm -rf certs
```
