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

The script prints your tenant ID and a tenant-specific OCI hostname at the end:

```
══════════════════════════════════════════════════════
  Setup complete!

  Tenant ID : 01920abc-...
  OCI Host  : 01920abc-....localhost:8080

  Use this hostname directly in image references:

    docker pull 01920abc-....localhost:8080/library/nginx:1.25.3
══════════════════════════════════════════════════════
```

## Try it out

### Registry-hostname flow

This is the primary hosted-registry UX. It is closer to Artifactory-style remote repositories than the local mirror flow because clients pull through the firewall hostname directly.

```bash
TENANT_ID="<id from setup>"
TENANT_HOST="${TENANT_ID}.localhost:8080"

# Allowed — version tag not blocked by the mutable-tag policy
curl -s \
  "http://${TENANT_HOST}/v2/library/nginx/manifests/1.25.3" \
  -o /dev/null -w "%{http_code}\n"
# → 200

# Denied — mutable tag "latest"
curl -s \
  "http://${TENANT_HOST}/v2/library/nginx/manifests/latest" \
  -o /dev/null -w "%{http_code}\n"
# → 403

# See the deny reason
curl -s \
  "http://${TENANT_HOST}/v2/library/nginx/manifests/latest" | jq .
# {
#   "errors": [
#     {
#       "code": "DENIED",
#       "message": "policy \"block-mutable-tags\" denied: mutable tag \"latest\" is not allowed"
#     }
#   ]
# }
```

If Docker is talking to the firewall hostname directly, use image references like:

```bash
docker pull "${TENANT_HOST}/library/nginx:1.25.3"   # allowed
docker pull "${TENANT_HOST}/library/nginx:latest"   # denied
```

`docker login` is not required for this example. The firewall currently supports host-based tenant routing for anonymous pulls, but it does not implement OCI registry authentication.

## Optional: configure Docker daemon as a mirror

Use this only when you want local `docker pull nginx:1.25.3` traffic to be redirected through the firewall without changing image names.

Point a tenant-specific hostname at the firewall and add it to `/etc/docker/daemon.json`.
For local development, map `<tenant-id>.localhost` to `127.0.0.1` if your environment does not already resolve `*.localhost`.

Example `/etc/hosts` entry:

```text
127.0.0.1 <tenant-id>.localhost
```

Example `/etc/docker/daemon.json`:

```json
{
  "registry-mirrors": ["http://<tenant-id>.localhost:8080"],
  "insecure-registries": ["<tenant-id>.localhost:8080"]
}
```

> **Note:** OCI tenant selection for Docker-compatible traffic is host-based. The firewall derives the tenant from the left-most hostname label and still accepts `X-Tenant-ID` as a direct-test fallback for raw HTTP clients.

Once the mirror is configured, regular Docker pulls are intercepted:

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

The import endpoint also accepts `application/json` with the same schema.

## Policy evaluation order

Policies are sorted by `priority` (ascending) then `name`. A **deny** result from any policy wins immediately — lower priority numbers are checked first. The `allow-internal-images` policy has `priority: 5`, so it short-circuits all deny rules for your own registry.
