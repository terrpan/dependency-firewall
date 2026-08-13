# npm proxy example

This example creates one tenant, registers `registry.npmjs.org`, and imports the six parser-valid policies in [`policy.yaml`](./policy.yaml):

- CVSS at or above 7.0;
- packages newer than 7 days;
- packages older than 730 days (disabled by default);
- blocked namespaces;
- approved SPDX licenses;
- a positive match for internal namespaces.

The allowlist does not exempt internal packages from deny rules. Dependency Firewall evaluates every applicable rule and any deny wins.

## Prerequisites

- running firewall (see the root [README](../../README.md));
- `curl` and `jq`;
- the Node version in [`.nvmrc`](./.nvmrc) for npm commands.

The public management and proxy HTTP endpoints used by this local example are not authenticated. Do not expose this topology directly.

## Setup

```bash
docker compose up --build -d
chmod +x setup.sh
./setup.sh
```

Pass a different all-in-one/control-plane URL if needed:

```bash
./setup.sh http://firewall.internal:8080
```

The script prints the tenant ID and writes a local `.npmrc`. With the example's single npm upstream, the tenant-only compatibility path resolves that upstream:

```ini
registry=http://localhost:8080/npm/t/<tenant-id>/
```

For an explicit upstream—recommended when a tenant has more than one—use:

```ini
registry=http://localhost:8080/npm/t/<tenant-id>/u/<upstream-id>/
```

## Exercise the proxy

```bash
npm install express

curl -H 'X-Tenant-ID: <tenant-id>' \
  http://localhost:8080/npm/express
```

Bare packuments are forwarded without version-level enrichment or decision persistence. Versioned metadata, resolved dist-tags, and tarballs are evaluated.

## Inspect results

```bash
curl -H 'X-Tenant-ID: <tenant-id>' \
  'http://localhost:8080/api/v1/evaluations?limit=20'

curl -H 'X-Tenant-ID: <tenant-id>' \
  'http://localhost:8080/api/v1/dependency-graphs?limit=100'
```

Dependency graphs require a running graph worker or `dependency_graph.run_in_process=true`. The default all-in-one setting is false.

## Re-import policies

```bash
curl -sS -X POST http://localhost:8080/api/v1/policies/import \
  -H 'Content-Type: application/x-yaml' \
  -H 'X-Tenant-ID: <tenant-id>' \
  --data-binary @policy.yaml
```

The endpoint also accepts JSON with the same required per-item `schema_version` field.
