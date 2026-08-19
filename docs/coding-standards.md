# Coding Standards

## Go standards

- Use context.Context as the first parameter in public methods.
- Prefer explicit constructors such as NewService or NewRepository.
- Keep interfaces small and place them near the consuming code.
- Avoid global mutable state.
- Configure tracing through providers and explicit construction patterns; do not mutate package-level tracer variables in tests.
- Prefer standard library facilities unless a dependency provides clear value.

### Linting and formatting

`.golangci.yml` is the source of truth for Go formatters, linters, and their thresholds. Run `make fmt` before `make lint`; use `make lint-fix` for safe automatic fixes. A lint suppression must name the linter and explain why the finding is not actionable. Do not use blanket `//nolint` directives.

The Go lint job runs for every pull request that changes the Go module or lint configuration. To install the same checks as local git hooks, run `make hooks-install` once per clone. This bootstraps [`lefthook`](https://github.com/evilmartians/lefthook) and the Go-based [`commitlint`](https://github.com/conventionalcommit/commitlint) via `go install`, then installs the hooks. The hooks use the locally installed `golangci-lint`; CI pins the project version so upgrades are explicit and reviewable.

The `commit-msg` hook validates that every commit message follows Conventional Commits with one of the allowed types from `.commitlint.yaml` (`feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, or `chore`). The `type`, `scope`, and `description` must be lower-case.

Example:

```text
feat(proxy): add npm package vulnerability lookup

- Resolve package name to latest version
- Query upstream scorecard API for vulnerabilities
```

### Web linting and formatting

The `web/` directory has its own linting toolchain; it never touches files outside `web/`.

- `npm --prefix web run lint` runs ESLint, Stylelint, and Prettier validation.
- `npm --prefix web run lint:code` runs ESLint with type-aware TypeScript rules, React correctness, and JSX accessibility rules.
- `npm --prefix web run lint:css` runs Stylelint on CSS Modules.
- `npm --prefix web run format` writes Prettier formatting; `npm --prefix web run format:check` validates it.
- `web/eslint.config.js`, `web/stylelint.config.js`, and `web/.prettierrc.json` are the sources of truth.

Generated artifacts under `web/src/lib/api/generated/` and the work-in-progress `web/src/pages/OrganizationsPage.*` files are excluded from linting and formatting until their API contract exists.

The web CI job and the lefthook `web-lint` command run `npm --prefix web run lint` for every change under `web/`.

## Layering standards

- Handlers only parse requests and render responses.
- Services orchestrate business workflows.
- Repositories only persist and load data.
- Policy packages evaluate policy and do not perform I/O.
- Control-plane handlers normally call core services. Existing read-oriented handlers may consume core repository ports; delivery must not depend on infrastructure implementations or issue direct SQL/Valkey operations.
- Delivery request bodies must decode into delivery-layer request DTOs, not domain models.
- Delivery response DTOs stay in delivery. Core types must not be shaped around JSON responses.
- Shared ports in core must use protocol-neutral names when they are used by more than one ecosystem.
- Protocol-specific terms such as manifest, blob, tarball, and tag belong in delivery or ecosystem-specific infrastructure packages.

### Boundary validation

- Decode external JSON/YAML into typed delivery or configuration DTOs before
  entering core workflows.
- Declarative validation libraries may handle structural boundary concerns such
  as required fields and formats when they remove repetitive validation code.
- Keep business invariants in explicit typed core/domain validation rather than
  encoding them in delivery-layer validation rules.

## Web UI standards

- Follow the principles and review checklist in [`ui-redesign.md`](./ui-redesign.md).
- Import reusable primitives and patterns through `web/src/ui/index.ts`.
- Keep primitives and patterns independent of APIs, React Query, routing, tenant state, auth providers, and feature modules.
- Keep domain behavior in `web/src/features` and route composition in pages. Preserve route-level lazy loading and keep D3 isolated to dependency graphs.
- Use CSS Modules for application, component, feature, and route styling. Global CSS is limited to tokens, reset, fonts, and document defaults.
- Reuse semantic tokens. Do not introduce route-specific colors or spacing into global styles.
- Delete superseded selectors, components, tokens, and tests in the same migration that makes them obsolete.
- Treat light and dark themes, keyboard operation, visible focus, reduced motion, and responsive behavior as acceptance requirements.
- UI changes pass `npm run lint`, `npm run build`, relevant mocked Playwright tests, and `git diff --check`.

## HTTP clients and streaming

- Reusable HTTP client types contain reusable configuration and dependencies
  only. Never retain `*http.Request`, request bodies, headers, URL parameters,
  or other per-request mutable state on a shared client.
- Construct a fresh request for each operation and attach request-specific state
  to that request.
- Treat `io.Reader` values as consumable. If a request body must be replayed,
  retain bounded source data and recreate the reader or provide `GetBody`.
- Avoid unbounded buffering of artifact content; preserve streaming where
  practical.
- `io.Pipe` producers must always terminate on success or failure. Multipart and
  other ordered streams must be written sequentially; concurrent or out-of-order
  writes can corrupt the stream.

## API Response DTOs

- **Always use response DTOs in the delivery layer**, never return domain models directly.
- Response DTOs must define `json` tags with lowercase, snake_case field names (e.g., `json:"created_at"`).
- Create converter functions to transform domain models to response DTOs (e.g., `toTenantResponse(t *domain.Tenant)`).
- Keep response DTOs and converters in delivery-owned, domain-focused files. Use `response.go` for genuinely shared API response shapes; do not force unrelated resource DTOs into one file.
- This ensures:
  - API contracts are stable and decoupled from internal domain model changes
  - JSON serialization uses consistent, developer-friendly lowercase naming
  - Omit internal fields (like `TenantID`) from responses when not needed for API consumers

## Error handling

- Return typed or categorized errors from core and infrastructure.
- Wrap lower-level errors with context.
- Translate internal errors into stable API or proxy responses at the delivery boundary.

## Testing

- Use table-driven tests.
- Unit test normalization rules.
- Unit test policy conditions and deny precedence.
- Service tests should use mocked ports.
- Repository tests must verify tenant scoping.
- Use testcontainers or similar for integration tests against PostgreSQL and Valkey.
- Use testify package for tests
- Browser tests should assert behavior and accessibility through roles, labels, keyboard input, and stable application state. Screenshots support review but do not replace behavioral assertions.

## Documentation

- Keep design documentation concise, structured, and implementation-oriented.
- Use established terms such as delivery, core, infrastructure, `tenant_id`,
  Valkey, and upstream consistently.
- Clearly distinguish control-plane management behavior from data-plane proxy
  behavior.
- Clearly distinguish implemented behavior from possible future work.
