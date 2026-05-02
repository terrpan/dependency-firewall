# Adding a policy type

## Goal

Add a new policy type in core without breaking layering, schema handling, or the generated control-plane metadata.

## Checklist

### 1. Define the domain type and typed config

Update `internal/core/domain/types.go`:

- add the new `domain.PolicyType` constant
- add a typed config struct that implements `domain.PolicyConfig`
- keep validation on the config struct explicit

If the new policy needs new upstream compatibility signals, add them in `internal/core/domain/upstream_capability.go`.

### 2. Wire parsing and typed config decoding

Update the core policy package:

- `internal/core/policy/parser.go`
  - add the new type to `knownPolicyTypes`
- `internal/core/policy/config.go`
  - add decode support for the new config type and schema version
- `internal/core/policy/dsl.go`
  - make sure YAML/JSON import definitions still map cleanly into the typed config shape

If you change an existing stored config shape, add an explicit PostgreSQL migration instead of runtime compatibility code.

### 3. Register catalog metadata

Update `internal/core/policy/catalog.go`:

- `Summary`
- `Description`
- `Help`
- `Example`
- `CurrentSchemaVersion`
- `SupportedSchemaVersions`
- `SupportedActions`
- `SupportedEcosystems`
- `RequiredCapabilities`

This catalog drives:

- schema-version checks
- `GET /api/v1/policy-types`
- control-plane UI hints
- upstream compatibility filtering

### 4. Implement the evaluator

Add the condition implementation under `internal/core/policy/condition/` and register it in `internal/core/policy/condition/condition.go`.

The evaluator must stay pure:

- no HTTP types
- no PostgreSQL
- no Valkey
- no upstream calls

### 5. Extend validation rules

Update `internal/core/policy/validate.go` when the new type has action-specific rules or other business invariants.

Examples:

- deny-only policy types
- fail-closed behavior requirements
- type-specific config constraints beyond the config struct itself

### 6. Thread metadata into the UI when needed

The policy type catalog is exposed automatically through the API, but the guided UI still has a small field-rendering layer.

If the new type needs custom wizard fields, update:

- `web/src/features/policies/draft.ts`
- optionally `web/src/pages/PoliciesPage.tsx` if the flow needs new copy or presentation

After any control-plane contract or policy catalog change, regenerate the web API types:

```bash
npm --prefix web run generate:api
```

or from `web/`:

```bash
npm run generate:api
```

### 7. Add tests

At minimum, cover:

- config decode + validation
- the condition evaluator
- catalog registration
- policy service behavior if compatibility or lifecycle rules changed
- API behavior if request/response metadata changed

Typical files to update:

- `internal/core/policy/catalog_test.go`
- `internal/core/service/policy_test.go`
- `internal/delivery/api/api_test.go`
- condition-specific tests in `internal/core/policy/condition/`

### 8. Update docs

Update docs when behavior changes:

- `docs/policy-engine.md` for semantics and requirements
- `README.md` if the policy is user-facing
- `web/README.md` if the UI or API generation workflow changed

## Validation commands

```bash
go test ./...
go test -tags=integration ./internal/infra/postgres
npm --prefix web run generate:api
npm --prefix web run build
npm --prefix web run lint
```

## Design guardrails

- keep business logic in core
- keep delivery limited to request/response parsing
- keep persistence concerns in infrastructure
- use typed config structs, not `map[string]any`, in core workflows
- use explicit schema-version handling for breaking config changes
