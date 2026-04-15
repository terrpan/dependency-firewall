#!/usr/bin/env bash
# setup.sh — Bootstrap the npm proxy example.
#
# Creates a tenant, registers an npm upstream, and imports the example
# policy set. Prints the tenant ID and .npmrc snippet at the end.
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
echo "==> Creating tenant 'npm-example-$(date +%s)' ..."
TENANT=$(curl -sf -X POST "${FIREWALL}/api/v1/tenants" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"npm-example-$(date +%s)\"}")
TENANT_ID=$(echo "$TENANT" | jq -r '.id')
echo "    tenant_id: ${TENANT_ID}"

echo
echo "==> Registering npm upstream (registry.npmjs.org) ..."
curl -sf -X POST "${FIREWALL}/api/v1/upstreams" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -d '{
    "name":      "npmjs-public",
    "ecosystem": "npm",
    "base_url":  "https://registry.npmjs.org"
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
echo ""
echo "  To use the npm proxy, add this to your .npmrc:"
echo ""
echo "    registry=http://localhost:8080/npm/t/${TENANT_ID}/"
echo ""
echo "  Or pass the header manually (alternative method):"
echo ""
echo "    curl -H \"X-Tenant-ID: ${TENANT_ID}\" \\"
echo "         http://localhost:8080/npm/express"
echo ""
echo "  Review decisions:"
echo ""
echo "    curl -H \"X-Tenant-ID: ${TENANT_ID}\" \\"
echo "         \"${FIREWALL}/api/v1/evaluations?limit=20\" | jq ."
echo "══════════════════════════════════════════════════════"
