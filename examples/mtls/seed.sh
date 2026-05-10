#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

control_plane_url="${FIREWALL_CONTROL_PLANE_URL:-http://localhost:8080}"
tenant_name="Tenant A"

echo "Creating tenant through the control-plane API..."
tenant_response="$(curl -s -X POST "$control_plane_url/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$tenant_name\"}")"

tenant_id="$(printf '%s\n' "$tenant_response" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [ -z "$tenant_id" ]; then
  echo "Failed to parse tenant id from response:" >&2
  echo "$tenant_response" >&2
  exit 1
fi

echo "Created tenant $tenant_id"
echo "Creating OCI upstream through the control-plane API..."

curl -s -X POST "$control_plane_url/api/v1/upstreams" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $tenant_id" \
  -d '{
    "name": "docker-hub",
    "ecosystem": "oci",
    "base_url": "https://registry-1.docker.io",
    "capabilities": ["manifest_digest_lookup"]
  }'
echo

echo "Use this tenant ID for proxy requests: $tenant_id"
