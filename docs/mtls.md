# mTLS Configuration

Split `control-plane` and `proxy` deployments must use mTLS for bundle and ingest gRPC. This connection carries tenant bundles, durable decision writes, audit events, and authenticated upstream auth envelopes when OCI upstream auth is configured.

The configuration is process-local. In a split deployment, mount a control-plane config and the control-plane server certificate/key into the control-plane container, and mount a proxy config and the proxy client certificate/key into each proxy container. Do not mount the proxy private key into the control plane or the control-plane private key into the proxy.

## Security model

```mermaid
flowchart LR
    proxy[Proxy runtime]
    proxyCert[Proxy client certificate]
    mtls[mTLS transport]
    authz[bundle.tls.authorized_clients]
    bundle[Bundle RPC]
    ingest[Ingest RPC]
    tenantData[Tenant runtime data]

    proxy --> proxyCert
    proxyCert --> mtls
    mtls --> authz
    authz -->|identity allowed for tenant_id| bundle
    authz -->|identity allowed for tenant_id| ingest
    bundle --> tenantData
    ingest --> tenantData
```

mTLS authenticates the process on each side of the connection. Tenant authorization is a separate check: the control plane reads the proxy certificate identity and verifies that identity is allowed to access the `tenant_id` carried by the bundle or ingest RPC.

For bundle delivery, the proxy client certificate is also the recipient key for upstream auth secrets. The control plane encrypts each configured upstream password/PAT/token to the requesting proxy certificate public key before placing it in the bundle response. The proxy keeps those version-2 envelopes in the runtime bundle cache and decrypts them with its local certificate private key only while constructing outbound OCI registry auth.

## Certificate requirements

- Use a private CA or workload identity provider controlled by the deployment.
- Do not commit private keys to the repository or bake them into public images.
- The control-plane server certificate must be valid for the name the proxy dials, or the proxy must set `bundle.tls.server_name_override`.
- The proxy client certificate must contain a stable identity in a DNS SAN, URI SAN, email SAN, or Common Name.
- The control plane must list that exact identity in `bundle.tls.authorized_clients`.
- Treat proxy private keys as bundle-secret decryption keys. A proxy can decrypt only envelopes encrypted to its own certificate public key.

The examples below use DNS SANs because they are easy to issue and understand in local and self-managed deployments. The same authorization model works with any stable certificate identity the code can extract. SPIFFE URI SANs are also supported when a deployment actually uses SPIFFE/SPIRE or another workload identity system that issues SPIFFE IDs.

| Certificate field | Example `authorized_clients.identity` |
| --- | --- |
| DNS SAN | `proxy-a.firewall.internal` |
| URI SAN | `spiffe://dependency-firewall/proxy/proxy-a` |
| Email SAN | `proxy-a@firewall.internal` |
| Common Name | `proxy-a` |

## Control-plane config

The control plane listens for bundle and ingest gRPC on `bundle.listen_addr`. In split deployments, `bundle.tls.mode` must be `mtls`, and `bundle.tls.authorized_clients` must map client certificate identities to tenant IDs. The only exception is the explicit `allow_insecure_control_plane` local-development override described below.

This config belongs in the control-plane process/container. It needs the CA bundle, the control-plane server certificate/key, and the list of proxy identities that may access tenants.

```yaml
runtime:
  mode: control-plane

bundle:
  listen_addr: ":9090"
  tls:
    mode: mtls
    ca_file: "/etc/firewall/tls/ca.pem"
    cert_file: "/etc/firewall/tls/control-plane.pem"
    key_file: "/etc/firewall/tls/control-plane-key.pem"
    authorized_clients:
      - identity: "proxy-a.firewall.internal"
        tenant_ids:
          - "tenant-a"
          - "tenant-b"
      - identity: "admin-proxy.firewall.internal"
        tenant_ids:
          - "*"
```

`tenant_ids: ["*"]` grants that proxy certificate identity access to every tenant. Use it only for intentionally shared administrative proxies.

For local development only, a control-plane process can explicitly opt out of this requirement:

```yaml
runtime:
  mode: control-plane

bundle:
  tls:
    mode: insecure
    allow_insecure_control_plane: true
```

When this override is active, startup logs emit a warning that control-plane gRPC is running without mTLS. Do not use this for shared environments or any deployment that carries authenticated upstream secrets.

## Proxy config

The proxy dials the control plane using `bundle.control_plane_addr`. In `proxy` mode, `bundle.tls.mode` must be `mtls`.

This config belongs in the proxy process/container. It needs the CA bundle and that proxy's client certificate/key. It does not need `authorized_clients`; tenant authorization is enforced by the control plane.

```yaml
runtime:
  mode: proxy

bundle:
  control_plane_addr: "control-plane.firewall.svc.cluster.local:9090"
  refresh_interval: 30s
  tls:
    mode: mtls
    ca_file: "/etc/firewall/tls/ca.pem"
    cert_file: "/etc/firewall/tls/proxy-a.pem"
    key_file: "/etc/firewall/tls/proxy-a-key.pem"
    server_name_override: "control-plane.firewall.svc.cluster.local"
```

Leave `server_name_override` empty when the dial address already matches the control-plane certificate SAN. Set it only when the network address and certificate name differ, such as dialing an IP address while the certificate is issued for a DNS name.

## Testing certificates

The following commands create a local CA plus one control-plane server certificate and one proxy client certificate for development tests. Do not use these keys in production.

For a runnable split-mode Docker Compose example with separate mounted configs, see [`examples/mtls`](../examples/mtls/README.md).

```bash
mkdir -p .local/mtls

openssl genrsa -out .local/mtls/ca-key.pem 4096
openssl req -x509 -new -nodes \
  -key .local/mtls/ca-key.pem \
  -sha256 -days 30 \
  -subj "/CN=dependency-firewall-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out .local/mtls/ca.pem

openssl genrsa -out .local/mtls/control-plane-key.pem 2048
openssl req -new \
  -key .local/mtls/control-plane-key.pem \
  -subj "/CN=control-plane.firewall.local" \
  -out .local/mtls/control-plane.csr
openssl x509 -req \
  -in .local/mtls/control-plane.csr \
  -CA .local/mtls/ca.pem \
  -CAkey .local/mtls/ca-key.pem \
  -CAcreateserial \
  -out .local/mtls/control-plane.pem \
  -days 30 -sha256 \
  -extfile <(printf "subjectAltName=DNS:control-plane.firewall.local,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")

openssl genrsa -out .local/mtls/proxy-a-key.pem 2048
openssl req -new \
  -key .local/mtls/proxy-a-key.pem \
  -subj "/CN=proxy-a" \
  -out .local/mtls/proxy-a.csr
openssl x509 -req \
  -in .local/mtls/proxy-a.csr \
  -CA .local/mtls/ca.pem \
  -CAkey .local/mtls/ca-key.pem \
  -CAcreateserial \
  -out .local/mtls/proxy-a.pem \
  -days 30 -sha256 \
  -extfile <(printf "subjectAltName=DNS:proxy-a.firewall.local\nextendedKeyUsage=clientAuth\n")
```

Use these paths in the control-plane config file mounted into the control-plane container:

```yaml
bundle:
  listen_addr: ":9090"
  tls:
    mode: mtls
    ca_file: ".local/mtls/ca.pem"
    cert_file: ".local/mtls/control-plane.pem"
    key_file: ".local/mtls/control-plane-key.pem"
    authorized_clients:
      - identity: "proxy-a.firewall.local"
        tenant_ids:
          - "tenant-a"
```

Use these paths in the proxy config file mounted into the proxy container:

```yaml
bundle:
  control_plane_addr: "127.0.0.1:9090"
  tls:
    mode: mtls
    ca_file: ".local/mtls/ca.pem"
    cert_file: ".local/mtls/proxy-a.pem"
    key_file: ".local/mtls/proxy-a-key.pem"
    server_name_override: "control-plane.firewall.local"
```

The proxy certificate DNS SAN is `proxy-a.firewall.local`, so the control-plane `authorized_clients.identity` must use that exact value. If you use a URI SAN, email SAN, or Common Name instead, change the identity value accordingly.

## Automatic split-proxy enrollment

When `enrollment.enabled` is true, the control plane additionally trusts the configured enrollment issuer CA for client verification. It keeps existing manual client roots and static `authorized_clients` compatibility. Database state has precedence for identities issued by enrollment: inactive, revoked, expired, or wrong-Tenant identities are denied without static fallback.

The enrollment issuer requires a CA certificate and separate CA private-key file. Startup validates the key match, CA constraints/current validity, and that the issuer key is not the control-plane server key. Issued certificates have a random serial, one server-generated URI SAN, digital-signature usage, and client-auth EKU. Their configurable validity defaults to 30 days and is capped by issuer expiry.

A proxy creates its P-256 key locally, enrolls over system-trusted HTTPS, and receives the client chain, existing gRPC server trust bundle, public gRPC address, and server name. An operator may set `enrollment.additional_ca_file` (or `FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE`) to a read-only mounted PEM bundle for an internal PKI or local development TLS bridge; it is appended to system roots only for the initial enrollment HTTPS client. It is never fetched from the enrollment endpoint and does not change gRPC mTLS trust. This proxy-only setting is not a control-plane trust configuration. No private key crosses the API or is written to disk. The in-memory key also decrypts the existing ECDSA hybrid upstream-secret envelope. Restart requires activation again; renewal and rotation are not implemented.

Control-plane enrollment configuration includes the public API/verification URLs, public gRPC address and server name, base64 32-byte HMAC key, expiry/poll timing, issuer files, and certificate validity. A proxy needs only the public enrollment API URL in addition to its normal Valkey/runtime settings. Non-loopback enrollment HTTP is rejected. [`examples/enrollment`](../examples/enrollment/README.md) provides a local-development Compose topology using Caddy and the proxy additional-CA setting for enrollment HTTPS only; gRPC remains direct end-to-end mTLS. Hosted proxies, Helm/Kubernetes, persistent keys, external agents, HA coordination, enterprise forward proxies, and CA-bundle distribution remain unavailable.

The root development topology can add the same Caddy bridge with `make up ENROLLMENT=1`. It uses only development certificates and a development HMAC key. Start the enrolled proxy separately; the existing `proxy` keeps its manually mounted test certificate, which preserves the ordinary `make up` behavior.

### Local development with Caddy

This is a local-development path only. Caddy terminates the enrollment HTTPS
request and the proxy trusts Caddy's locally generated root for that one
request. Caddy never handles the bundle or ingest gRPC connection; the enrolled
proxy connects directly to the control plane's host-published gRPC port with the
certificate it receives during enrollment.

Start the local control plane and Caddy:

```bash
make up ENROLLMENT=1
```

After Caddy has started, copy its root certificate from the Docker volume to a
host file for a separately started proxy:

```bash
mkdir -p .local
docker compose -f docker-compose.yml -f docker-compose.enrollment.yml \
  --profile enrollment \
  cp caddy:/data/caddy/pki/authorities/local/root.crt \
  .local/caddy-root.crt
```

Run that proxy on its own network with its own Valkey dependency. Mount the
copied file read-only and configure only the initial enrollment client to trust
it:

```bash
docker network inspect dependency-firewall >/dev/null 2>&1 || \
  docker network create dependency-firewall

if docker container inspect dependency-firewall-valkey >/dev/null 2>&1; then
  docker start dependency-firewall-valkey >/dev/null
else
  docker run -d --name dependency-firewall-valkey \
    --network dependency-firewall \
    valkey/valkey:8-alpine
fi

docker run --rm --name dependency-firewall-enrolled-proxy \
  --network dependency-firewall \
  --add-host host.docker.internal:host-gateway \
  -v "$PWD/.local/caddy-root.crt:/etc/firewall/additional-ca.pem:ro" \
  -e FIREWALL_RUNTIME_MODE=proxy \
  -e FIREWALL_BUNDLE_TLS_MODE=mtls \
  -e FIREWALL_ENROLLMENT_ENABLED=true \
  -e FIREWALL_ENROLLMENT_PUBLIC_API_URL=https://host.docker.internal:8443 \
  -e FIREWALL_ENROLLMENT_ADDITIONAL_CA_FILE=/etc/firewall/additional-ca.pem \
  -e FIREWALL_VALKEY_ADDR=dependency-firewall-valkey:6379 \
  dependency-firewall:latest
```

`host.docker.internal` reaches the Docker host from the separately started
proxy. Docker Desktop provides it automatically; `--add-host ...:host-gateway`
provides the equivalent mapping on Linux. Caddy creates its root on first start;
rerun the copy command if it was not available yet. Do not use this CA, the
development HMAC key, or this Caddy topology in a shared or production
deployment.

## Validation rules

- `runtime.mode=control-plane` requires `bundle.tls.mode=mtls`, unless `bundle.tls.allow_insecure_control_plane=true` is explicitly set for local development.
- `runtime.mode=proxy` requires `bundle.tls.mode=mtls`.
- `runtime.mode=dependency-graph-worker` requires `bundle.tls.mode=mtls` and uses `bundle.control_plane_addr` to claim and complete graph jobs.
- In worker mode, the `bundle` section is transport-only: it configures the mTLS client to the control plane, not tenant bundle retrieval or caching.
- `bundle.tls.mode=mtls` requires `ca_file`, `cert_file`, and `key_file`, except an enrollment-enabled proxy receives those materials in memory.
- `runtime.mode=control-plane` plus `bundle.tls.mode=mtls` requires at least one `authorized_clients` entry unless database-backed automatic enrollment is enabled.
- Authenticated OCI upstream secrets are delivered in bundles only when the bundle transport is mTLS-protected and tenant-authorized.
- Split-mode proxy runtime requires bundle-delivered auth secrets to be version-2 encrypted envelopes and rejects plaintext bundle secrets. All-in-one mode uses the legacy-compatible resolver for local in-process flows.

## Operational checklist

- Issue separate certificates for each proxy and dependency graph worker deployment.
- Keep control-plane, proxy, and dependency graph worker configs separate in split deployments; each process should receive only its own certificate/key.
- Keep the worker's `bundle` config limited to the control-plane address and mTLS client credentials; it should not reuse proxy bundle cache settings.
- Authorize each proxy and worker identity only for the tenants it should serve. Set a tenant-scoped worker's `dependency_graph.tenant_id` to the same concrete tenant ID. Use `"*"` in both places only for a global worker that should claim jobs across all tenants.
- Rotate proxy certificates by adding the new identity to `authorized_clients`, deploying the new cert, then removing the old identity.
- Protect key files with filesystem permissions readable only by the firewall process.
- Use one CA bundle for the trust anchors that should be allowed to participate in control-plane gRPC.
- Rotate proxy certificates deliberately: new bundle envelopes are encrypted to the active proxy certificate public key, so a running proxy must have the matching private key.

## Tenant-scoped workers

Worker claim and watch requests carry the configured `dependency_graph.tenant_id`. The control plane authorizes that tenant against the worker certificate, filters PostgreSQL claims to it, and sends only matching wake-up notifications. Completion and failure requests continue to be authorized using the tenant on the claimed job.

For an authorization-enforced tenant worker, configure both sides with the same tenant:

```yaml
# worker.yaml
dependency_graph:
  tenant_id: "00000000-0000-0000-0000-000000000001"

# control-plane.yaml
bundle:
  tls:
    authorized_clients:
      - identity: "tenant-a-worker.firewall.local"
        tenant_ids:
          - "00000000-0000-0000-0000-000000000001"
```

The default tenant scope is `"*"` for backward compatibility. It requires wildcard certificate authorization and is appropriate only for a worker intended to process every tenant.
