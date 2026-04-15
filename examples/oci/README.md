# OCI proxy example

This example walks through setting up the dependency firewall as an OCI (container image) registry proxy for a single tenant.

## What the setup script does

1. Waits for the firewall to be healthy
2. Creates a tenant called `oci-example`
3. Registers `registry-1.docker.io` (Docker Hub) as the upstream OCI registry
4. Imports the four policies in `policy.yaml`:
   - **block-mutable-tags** — deny images pulled by `latest`, `stable`, or `edge`
   - **block-vulnerable-images** — deny images with CVSS > 8.0
   - **block-untrusted-registries** — deny images from specific namespaces
   - **allow-internal-images** — unconditionally allow your own registry

## Prerequisites

- Firewall running (see root [README](../../README.md))
- `curl` and `jq` installed

## Run the setup

```bash
# Start the full stack if you haven't already
docker compose up --build -d

# Run setup (defaults to http://localhost:8080)
chmod +x setup.sh
./setup.sh

# Or point at a different host
./setup.sh http://firewall.internal:8080
```

The script prints your tenant ID and a Docker daemon config snippet at the end:

```
══════════════════════════════════════════════════════
  Setup complete!

  Tenant ID : 01920abc-...

  To proxy OCI pulls through the firewall, add this
  to /etc/docker/daemon.json and restart Docker:

    {
      "registry-mirrors": ["http://localhost:8080"]
    }
══════════════════════════════════════════════════════
```

## Try it out

```bash
TENANT_ID="<id from setup>"

# Allowed — pinned by immutable digest
curl -s -H "X-Tenant-ID: $TENANT_ID" \
  http://localhost:8080/v2/library/nginx/manifests/1.25.3 \
  -o /dev/null -w "%{http_code}\n"
# → 200

# Denied — mutable tag "latest"
curl -s -H "X-Tenant-ID: $TENANT_ID" \
  http://localhost:8080/v2/library/nginx/manifests/latest \
  -o /dev/null -w "%{http_code}\n"
# → 403

# See the deny reason
curl -s -H "X-Tenant-ID: $TENANT_ID" \
  http://localhost:8080/v2/library/nginx/manifests/latest | jq .
# {
#   "errors": [
#     {
#       "code": "DENIED",
#       "message": "policy \"block-mutable-tags\" denied: mutable tag \"latest\" is not allowed"
#     }
#   ]
# }
```

## Configure Docker daemon as a mirror

Add to `/etc/docker/daemon.json` and restart Docker:

```json
{
  "registry-mirrors": ["http://localhost:8080"]
}
```

> **Note:** Docker registry mirrors don't forward custom HTTP headers automatically. For header-based tenant routing, use the firewall behind a reverse proxy that injects `X-Tenant-ID`, or use host-based tenant resolution when implemented.

Once configured, regular Docker pulls are intercepted:

```bash
docker pull nginx:1.25.3      # allowed — pinned version
docker pull nginx:latest      # denied — mutable tag blocked
docker pull nginx              # denied — defaults to :latest
```

When denied, Docker shows:

```
Error response from daemon: pull access denied for nginx, repository does not exist
or may require 'docker login': denied: policy "block-mutable-tags" denied:
mutable tag "latest" is not allowed
```

## Review decisions

```bash
curl -H "X-Tenant-ID: $TENANT_ID" \
     "http://localhost:8080/api/v1/evaluations?limit=20" | jq .
```

## Customising policies

Edit `policy.yaml` and re-import to apply changes:

```bash
curl -X POST http://localhost:8080/api/v1/policies/import \
  -H "Content-Type: application/x-yaml" \
  -H "X-Tenant-ID: $TENANT_ID" \
  --data-binary @policy.yaml | jq .
```

## Policy evaluation order

Policies are sorted by `priority` (ascending) then `name`. A **deny** result from any policy wins immediately — lower priority numbers are checked first. The `allow-internal-images` policy has `priority: 5`, so it short-circuits all deny rules for your own registry.
