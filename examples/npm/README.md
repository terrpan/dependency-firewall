# npm proxy example

This example walks through setting up the dependency firewall as an npm registry proxy for a single tenant.

## What the setup script does

1. Waits for the firewall to be healthy
2. Creates a tenant called `npm-example`
3. Registers `registry.npmjs.org` as the upstream npm registry
4. Imports the five policies in `policy.yaml`:
   - **block-critical-vulnerabilities** — deny packages with CVSS > 7.0
   - **block-brand-new-packages** — deny packages published less than 7 days ago
   - **block-outdated-packages** — deny packages published more than 365 days ago
   - **block-untrusted-scopes** — deny known bad npm scopes
   - **allow-internal-packages** — unconditionally allow your own packages

## Prerequisites

- Firewall running (see root [README](../../README.md))
- `curl` and `jq` installed
- Node.js v24.11.1 or compatible (if using npm commands; see `.nvmrc`)

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

The script prints your tenant ID and an `.npmrc` snippet at the end:

```
══════════════════════════════════════════════════════
  Setup complete!

  Tenant ID : 01920abc-...

  To use the npm proxy, add this to your .npmrc:

    registry=http://localhost:8080/npm/t/01920abc-.../

  Or pass the header manually (alternative method):

    curl -H "X-Tenant-ID: 01920abc-..." \
         http://localhost:8080/npm/express
══════════════════════════════════════════════════════
```

## Try it out

```bash
TENANT_ID="<id from setup>"

# Fetch package metadata — should be allowed (express is well-established)
curl -H "X-Tenant-ID: $TENANT_ID" http://localhost:8080/npm/express | jq .name,.version

# Fetch a scoped package
curl -H "X-Tenant-ID: $TENANT_ID" "http://localhost:8080/npm/%40types%2Fnode" | jq .name

# A brand-new package will be denied (published < 7 days ago)
# The response is a JSON error that npm displays as a 403:
# {
#   "error": "policy \"block-brand-new-packages\" denied: package age 0 days is below minimum 7 days"
# }
```

## Configure npm

Add to your project's `.npmrc` (or `~/.npmrc`):

```ini
registry=http://localhost:8080/npm/t/<tenant-id>/
```

Replace `<tenant-id>` with your actual tenant ID from the setup output.

Then normal npm commands are proxied and evaluated:

```bash
npm install express          # evaluated and passed through if allowed
npm install some-new-package # blocked if published < 7 days ago
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
