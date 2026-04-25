#!/usr/bin/env bash
# setup.sh — Bootstrap the OCI proxy example.
#
# Creates a tenant, registers a Docker Hub OCI upstream, and imports the
# example policy set. Prints the tenant ID and tenant-specific OCI hostname at
# the end.
#
# Usage:
#   ./setup.sh [FIREWALL_URL]
#
# Defaults to http://localhost:8080 when FIREWALL_URL is not set.

set -euo pipefail

FIREWALL="${1:-${FIREWALL_URL:-http://localhost:8080}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── helpers ──────────────────────────────────────────────────────────────────

check_deps() {
  for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "error: '$cmd' is required but not installed" >&2
      exit 1
    fi
  done
}

wait_for_firewall() {
  echo "Waiting for firewall at ${FIREWALL} ..."
  local attempts=0
  until curl -sf "${FIREWALL}/healthz" -o /dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 30 ]; then
      echo "error: firewall did not become ready after 30 attempts" >&2
      exit 1
    fi
    sleep 2
  done
  echo "Firewall is ready."
}

# ── main ─────────────────────────────────────────────────────────────────────

check_deps
wait_for_firewall

echo
echo "==> Creating tenant 'oci-example-$(date +%s)' ..."
TENANT=$(curl -sf -X POST "${FIREWALL}/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"oci-example-$(date +%s)\"}")
TENANT_ID=$(echo "$TENANT" | jq -r '.id')
TENANT_HOST="${TENANT_ID}.localhost:8080"
echo "    tenant_id: ${TENANT_ID}"

echo
echo "==> Registering OCI upstream (Docker Hub) ..."
curl -sf -X POST "${FIREWALL}/api/v1/upstreams" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -d '{
    "name":      "docker-hub",
    "ecosystem": "oci",
    "base_url":  "https://registry-1.docker.io"
  }' | jq '{id, name, ecosystem, base_url}'

echo
echo "==> Importing policies from policy.yaml ..."
IMPORT=$(curl -sf -X POST "${FIREWALL}/api/v1/policies/import" \
  -H "Content-Type: application/x-yaml" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  --data-binary "@${SCRIPT_DIR}/policy.yaml")
echo "    $(echo "$IMPORT" | jq -r '"imported \(.imported) policies"')"

echo
echo "==> Listing active policies ..."
curl -sf "${FIREWALL}/api/v1/policies" \
  -H "X-Tenant-ID: ${TENANT_ID}" | jq '[.[] | {name, type, action, priority, enabled}]'

echo
echo "══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Tenant ID : ${TENANT_ID}"
echo "  OCI Host  : ${TENANT_HOST}"
echo ""
echo "  Use this hostname directly with Docker or other OCI clients:"
echo ""
echo "    docker pull ${TENANT_HOST}/library/nginx:1.25.3"
echo ""
echo "  OCI tenant routing is host-based for Docker-compatible traffic."
echo "  docker login is not required for this example."
echo "  For local transparent docker pull nginx:... workflows only,"
echo "  you can also configure Docker to use ${TENANT_HOST} as a mirror."
echo "  For direct curl tests:"
echo ""
echo "    # Allowed — version tag not blocked by the mutable-tag policy"
echo "    curl http://${TENANT_HOST}/v2/library/nginx/manifests/1.25.3"
echo ""
echo "    # Denied — mutable tag 'latest'"
echo "    curl http://${TENANT_HOST}/v2/library/nginx/manifests/latest"
echo ""
echo "  Review decisions:"
echo ""
echo "    curl -H \"X-Tenant-ID: ${TENANT_ID}\" \\"
echo "         \"${FIREWALL}/api/v1/evaluations?limit=20\" | jq ."
echo "══════════════════════════════════════════════════════"
