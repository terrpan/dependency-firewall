# Automatic proxy enrollment

This local-development example starts a split proxy without provisioning a
client certificate, private key, certificate identity, Tenant ID, or static
client allowlist. Caddy terminates enrollment HTTPS with its local CA and the
proxy mounts that CA only for the first enrollment connection.

```bash
docker compose -f examples/enrollment/docker-compose.yml up
```

Open the verification URI printed by the proxy and enter its one-time code.
After an authorized operator approves the selected Tenant and installation
name, the proxy receives a client certificate and connects. Credentials remain
in memory; restarting the proxy deliberately starts a new activation.

The proxy still requires Valkey for request-path caches. The example includes a
local Valkey service for that runtime dependency. Caddy publishes the
enrollment API at `https://localhost:8443` and forwards it to a control plane
listening on the Docker host at port `8080`.

Configure the local control plane with `enrollment.public_api_url` set to
`https://localhost:8443`. Its `enrollment.public_grpc_address` must remain a
direct mTLS endpoint reachable from the proxy, such as
`host.docker.internal:9090`; Caddy does not proxy gRPC because the control
plane must verify the enrolled proxy certificate itself. On Linux, the Compose
`host-gateway` mapping supplies `host.docker.internal`.

The Caddy service and its mounted additional CA are for local development only.
They are not a production enrollment or control-plane trust configuration.

Docker Compose is the only documented automatic-enrollment deployment today.
Helm, raw Kubernetes manifests, renewal, rotation, persistent proxy identity,
and hosted proxies are unavailable.
