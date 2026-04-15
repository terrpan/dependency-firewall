---
applyTo: "internal/core/policy/**/*.go,policies/**/*.yaml"
---

# Policy DSL Instructions

- Policies are defined in YAML and loaded into PostgreSQL.
- The DSL is the initial interface for managing policies before a UI exists.
- Each policy file targets a single tenant.
- deny overrides allow; evaluation is deterministic.
- Keep the DSL simple and declarative; avoid Turing-complete constructs.
