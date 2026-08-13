# OCI proxy example

This example creates one tenant, registers Docker Hub, and imports the four OCI-compatible policies in [`policy.yaml`](./policy.yaml):

- blocked mutable tags;
- blocked namespaces;
- a positive internal-namespace match;
- strict approved-namespace enforcement.

The allowlist does not short-circuit or override either deny rule. CVSS, Scorecard, and license enrichment are npm-only today and are intentionally absent from this OCI policy set.

## Prerequisites

- running firewall (see the root [README](../../README.md));
- `curl` and `jq`;
- host resolution for the tenant-specific local hostname when using Docker.

The firewall does not authenticate OCI clients. `docker login` is not required for this anonymous local example. Server-side upstream Basic/PAT and static bearer credentials are supported separately; see [proxy behavior](../../docs/proxy-behavior.md#registry-authentication).

## Setup

```bash
docker compose up --build -d
chmod +x setup.sh
./setup.sh
```

The script prints a tenant hostname. Because the example creates one OCI upstream, the tenant-only host uses that upstream:

```text
<tenant-id>.localhost:8080
```

With multiple OCI upstreams, use the explicit form:

```text
u-<upstream-id>.<tenant-id>.localhost:8080
```

## Manifest checks

```bash
TENANT_HOST='<tenant-id>.localhost:8080'

curl -sS "http://${TENANT_HOST}/v2/library/nginx/manifests/1.25.3"
curl -sS "http://${TENANT_HOST}/v2/library/nginx/manifests/latest"
```

The pinned tag can pass. `latest` is denied by `block-mutable-tags`. The current OCI surface is GET-only/pull-only.

```bash
docker pull "${TENANT_HOST}/library/nginx:1.25.3"
docker pull "${TENANT_HOST}/library/nginx:latest"
```

For local Docker, add the tenant hostname to `/etc/hosts` when your environment does not resolve `*.localhost`, and mark the HTTP registry insecure for development. Do not copy that HTTP configuration to a shared deployment.

## Blob gate

Blob requests do not run policy evaluation again. They require an allow decision for a manifest of the same tenant/repository during the preceding hour. The current lookup is not upstream-scoped; see [the documented constraint](../../docs/proxy-behavior.md#blobs).

## Inspect and update policies

```bash
curl -H 'X-Tenant-ID: <tenant-id>' \
  'http://localhost:8080/api/v1/evaluations?limit=20'

curl -sS -X POST http://localhost:8080/api/v1/policies/import \
  -H 'Content-Type: application/x-yaml' \
  -H 'X-Tenant-ID: <tenant-id>' \
  --data-binary @policy.yaml
```

Every policy item must include a supported `schema_version`.
