# Coding Standards

## Go standards

- Use context.Context as the first parameter in public methods.
- Prefer explicit constructors such as NewService or NewRepository.
- Keep interfaces small and place them near the consuming code.
- Avoid global mutable state.
- Configure tracing through providers and explicit construction patterns; do not mutate package-level tracer variables in tests.
- Prefer standard library facilities unless a dependency provides clear value.

## Layering standards

- Handlers only parse requests and render responses.
- Services orchestrate business workflows.
- Repositories only persist and load data.
- Policy packages evaluate policy and do not perform I/O.
- Control-plane handlers call core services, not repositories.
- Delivery request bodies must decode into delivery-layer request DTOs, not domain models.
- Delivery response DTOs stay in delivery. Core types must not be shaped around JSON responses.
- Shared ports in core must use protocol-neutral names when they are used by more than one ecosystem.
- Protocol-specific terms such as manifest, blob, tarball, and tag belong in delivery or ecosystem-specific infrastructure packages.

## API Response DTOs

- **Always use response DTOs in the delivery layer**, never return domain models directly.
- Response DTOs must define `json` tags with lowercase, snake_case field names (e.g., `json:"created_at"`).
- Create converter functions to transform domain models to response DTOs (e.g., `toTenantResponse(t *domain.Tenant)`).
- Centralize all response DTOs and converters in `internal/delivery/api/response.go`.
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
