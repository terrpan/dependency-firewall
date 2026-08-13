---
applyTo: "internal/core/policy/**/*.go,policies/**/*.yaml"
---

# Policy DSL Instructions

- Policies are defined in YAML and loaded into PostgreSQL.
- YAML/JSON import, the control-plane API, and the policy UI are current policy-management interfaces.
- Every policy item must include a supported `schema_version`.
- Each policy file targets a single tenant.
- deny overrides allow; evaluation is deterministic.
- Keep the DSL simple and declarative; avoid Turing-complete constructs.
