# Adding a policy type

## Goal

Add a new policy type in core without breaking layering, schema handling, or the generated control-plane metadata.

For upstream protocol/ecosystem extension work, use `docs/adding-upstream.md`.

## Checklist

### 1. Define the domain type and typed config

Update domain model files under `internal/core/domain/`:

- add the new `domain.PolicyType` constant in `internal/core/domain/policy.go`
- add a typed config struct that implements `domain.PolicyConfig` in a focused file under `internal/core/domain/`, named `policy_config_<concept>.go` (one file per policy domain concept; see existing `policy_config_cvss.go`, `policy_config_age.go`, `policy_config_mutable_tag.go`, `policy_config_namespace_list.go`, `policy_config_scorecard.go`, `policy_config_license.go`)
- keep validation on the config struct explicit

If the new policy needs new upstream compatibility signals, add them in `internal/core/domain/upstream_capability.go`.

### 2. Register the policy in one place

Add a small provider function in the closest `internal/core/policy/catalog_*.go` file, or create a new focused catalog file when the policy starts a new family.

- descriptor metadata (summary, help, schemas, supported actions/ecosystems, required capabilities)
- condition evaluator
- config constructor(s) by schema version
- config type matcher
- `requiresExternalMetadata` flag (true only when runtime enrichment is required)

Then add that provider to `policyDefinitionProviders` in `internal/core/policy/catalog.go`. `parser.go`, config decode, condition lookup, schema checks, and action compatibility all read from this registry.

Keep `internal/core/policy/dsl.go` aligned only when the policy document shape itself changes.

If you change an existing stored config shape, add an explicit PostgreSQL migration instead of runtime compatibility code.

### 3. Keep catalog metadata complete

Within the policy definition provider, make sure these descriptor fields are complete:

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

Add the condition implementation under `internal/core/policy/condition/` and reference it from the policy definition entry in `internal/core/policy/catalog.go`.

The evaluator must stay pure:

- no HTTP types
- no PostgreSQL
- no Valkey
- no upstream calls

The shared `target` block is evaluated by the policy engine before the type-specific condition. New conditions should consume the already-selected artifact and metadata; do not duplicate dependency-scope/type matching inside a condition. Add target-aware evaluator tests when the new type has unusual interactions with `dry_run`, missing metadata, or `on_unknown` warning behavior.

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
- descriptor metadata consumed by the API and policy-authoring UI
- target-aware evaluation with direct, transitive, and unknown context where relevant
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
- `GET /api/v1/policy-types` example/descriptor text used by API and UI clients
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
