# Authentication and authorization architecture

## Status and rollout

This document is the target contract for the Tenant, Organization, Team, and authorization refactor. The current checkout still has unauthenticated public HTTP routes; each implementation phase must keep that distinction explicit until the corresponding enforcement layer ships.

The rollout is additive and preserves every existing Tenant ID. Compatibility mode remains available for one release, emits a high-severity startup warning, and is forbidden in the SaaS deployment profile. It does not make unauthenticated public exposure safe.

## Scope hierarchy

```text
Tenant / Account
├── Account policies
├── Tenant-shared upstreams
└── Organization
    ├── Organization policies
    ├── Organization-shared upstreams
    └── Team
        ├── Team-local upstreams
        └── Approved exact-artifact policy waivers
```

- **Tenant / Account** is the immutable customer isolation boundary and maps to one external identity-provider organization. Existing Tenant IDs and npm/OCI routes are never rewritten.
- **Organization** is the primary operational scope. Local Organization roles grant permissions within it.
- **Team** limits where an Organization permission applies. Teams have memberships but no independent roles in v1.
- Tenant Owner and Admin inherit Organization Admin rights throughout their Tenant. Organization Admin bypasses Team membership only inside that Organization.
- Tenant Member has no Organization permission without a local Organization membership. Team membership never grants an action permission by itself.

Every customer-owned table retains `tenant_id`. Repositories load resources through Tenant plus Organization and, where applicable, Team predicates. Composite foreign keys must prevent cross-Tenant and cross-Organization references.

## Identity ownership

The core model is provider-neutral:

- `Principal` is the local audit and membership subject. Email is informational and never an authorization key.
- `tenant_identity_links(tenant_id, provider, external_id)` maps an external account to the immutable Tenant.
- `principal_identities(principal_id, provider, external_subject)` maps an external user to a Principal.
- Clerk owns sign-up, sessions, Tenant membership, invitations, account switching, and eventual SSO.
- Dependency Firewall owns Organizations, Organization roles, Teams, policy/upstream scope, waivers, data-plane credentials, and authorization audit.

The legacy `users` and `tenant_memberships` tables remain deprecated and read-only. They are not a second identity or Tenant-membership authority.

## Trust boundaries

| Boundary | Authentication | Authorization |
| --- | --- | --- |
| Human control plane | verified Clerk session JWT | Tenant role, local Organization role, Team scope |
| npm/OCI data plane | high-entropy opaque firewall credential | credential-bound Tenant, Organization, optional Team, and upstream visibility |
| Internal gRPC | existing mTLS client certificate | existing certificate-to-Tenant allowlist plus nested-scope ancestry validation |

These boundaries remain independent. Clerk sessions never enter the proxy hot path, and human RBAC never replaces the existing internal mTLS interceptors.

### Human request flow

```text
Bearer token
  -> provider adapter verifies the session
  -> external active account maps to a Tenant
  -> local Principal and Tenant enter request context
  -> handler authorizes permission and local scope
  -> repository applies Tenant/Organization/Team predicates
```

SaaS requests require an active external Organization. Personal-account sessions cannot select customer resources. Request `tenant_id`, `organization_id`, and `team_id` values are selectors, never authority. A supplied legacy `X-Tenant-ID` must equal the verified Tenant.

Authentication failures return `401`, known-scope permission denials return `403`, and forged or foreign resource identifiers return `404` without revealing whether the resource exists.

Control-plane deployments select `auth.mode=clerk` and configure the server-only
`auth.clerk.secret_key`, exact issuer and audience, and an allowlist of authorized
browser origins. The optional `auth.clerk.jwt_key` pins a public verification key;
otherwise the adapter caches Clerk JWKs and refreshes once on key rotation. The SPA
uses only `VITE_CLERK_PUBLISHABLE_KEY`; the Clerk secret is never exposed to Vite.

### Session bootstrap and reconciliation

`POST /api/v1/session/bootstrap` synchronously establishes the Tenant identity link and Principal after an account is created or activated. Webhooks reconcile changes, mark revocations, update names/status, and apply pending local assignments after invitation acceptance; webhook delivery is never an onboarding dependency.

Webhook event IDs are stored for replay protection. Ordinary requests accept verified five-minute claims until expiry, subject to earlier local deny markers. High-risk account membership, account policy, Tenant-shared upstream, account-waiver, and lifecycle operations perform a fresh provider membership check and fail closed.

## Permission model

Handlers request typed permissions; they do not compare role strings. A single versioned catalog expands canonical Tenant and Organization roles.

Canonical permissions are:

```text
account:read, account:manage, account:delete
members:read, members:invite, members:manage
organizations:read, organizations:create, organizations:manage
teams:read, teams:manage
policies:read, policies:write, policies:delete
waivers:request, waivers:approve
upstreams:read, upstreams:write, upstreams:delete
credentials:read, credentials:write, credentials:revoke
evaluations:read, dependency-graphs:read, audit:read
cache:invalidate
```

Authorization is evaluated in this order:

1. require an authenticated Principal;
2. resolve the verified external account to a local Tenant;
3. reject a mismatched client-selected Tenant;
4. require Tenant predicates on resource queries;
5. validate Organization ancestry;
6. resolve Tenant administrative inheritance or local Organization role;
7. expand the canonical role bundle;
8. require Team membership for Team-local scope unless an administrative bypass applies;
9. load by Tenant plus Organization/Team plus resource ID;
10. record privileged grants and all denials without leaking foreign resource existence.

Authorization decisions are not cached across requests in v1. Explicit SQL predicates and composite constraints are the primary isolation controls. PostgreSQL RLS is deferred until pooled-connection, worker, migration, and administrative transaction context has a dedicated design.

Every non-health, non-webhook control-plane operation must declare authentication and a permission. A registry test enforces this contract.

## Policy inheritance and waivers

Policies have exactly one scope:

- `account`: applies to every Organization and Team in the Tenant;
- `organization`: applies only to credentials selecting that Organization.

The evaluator loads account policies plus matching Organization policies and remains deny-wins. Existing policies migrate to non-waivable account policies.

Teams cannot create general allow policies. A waiver suppresses one referenced deny policy for one exact artifact:

- npm requires a normalized package name and exact version;
- OCI requires an exact repository and immutable digest;
- the policy must be enabled, deny, and explicitly waivable;
- requester and approver must be different Principals;
- account-policy waivers require Tenant approval; Organization-policy waivers require Organization approval;
- expiry is mandatory and limited to 30 days;
- another matching deny still wins.

Approval, rejection, revocation, and expiry are immutable audit events and invalidate the Tenant decision generation. A cached decision TTL cannot extend beyond the earliest applicable waiver expiry.

## Upstreams and data-plane credentials

Upstreams are `tenant_shared`, `organization_shared`, or `team_local`. Tenant-shared upstreams require Tenant administration. Organization-shared upstreams require a matching credential Organization. Team-local upstreams require a credential for that exact Team.

A data-plane credential selects exactly one Organization and optionally one Team. Secrets are generated with cryptographic randomness, shown once, and stored only as a public credential ID plus SHA-256 digest of the high-entropy secret. npm uses bearer authentication. OCI uses registry-compatible Basic authentication over TLS with the opaque token as password and a `/v2/` challenge when absent.

The routed Tenant must equal the credential Tenant. Client-provided Organization or Team headers never select scope. If multiple visible upstreams serve an ecosystem and the route does not select one, the request fails as ambiguous.

Tenant bundles carry verifier digests, scope identifiers, upstream visibility, policies, and waivers—never raw credentials. Policy last-known-good behavior remains, but credential verifiers have a separate maximum staleness of five minutes. Once exceeded, authentication fails with service unavailable rather than accepting potentially revoked credentials.

The one-release unauthenticated data-plane compatibility mode is restricted to the generated default Organization, Tenant-shared upstreams, and account policies.

## API compatibility

`GET /api/v1/session` returns only the active Tenant, Principal, local Organization memberships, effective permissions, and allowed actions. It never enumerates every Tenant.

New APIs are account/Organization/Team nested and derive Tenant from verified context. Request bodies cannot set `tenant_id`. Responses include explicit scope, `organization_id`, and optional `team_id`.

Scoped policy CRUD is exposed at `/api/v1/account/policies` and `/api/v1/organizations/{organization_id}/policies`. Scoped upstream CRUD is exposed at the corresponding account and Organization paths plus `/api/v1/organizations/{organization_id}/teams/{team_id}/upstreams`. Account mutations require a fresh external membership check; Organization and Team mutations use current local authorization assignments. Update and delete operations first load the resource through its exact ownership scope, so an inherited or visible resource cannot be mutated through a narrower route.

Legacy Tenant and flat resource endpoints remain behind compatibility mode for one release, and in authenticated mode any supplied Tenant must match the verified account. The compatibility-release contract requires `Deprecation` and `Sunset` headers before those routes are retired. Self-service Tenant deletion remains disabled until retention, billing, and recovery semantics exist.

## Audit requirements

Evaluation, decision, graph, and audit records capture Tenant, Organization, optional Team, upstream, and optional credential. Human mutations capture Principal and authorization outcome/reason. Denial records must be useful to operators without exposing foreign identifiers to the caller.

Cache identities include Tenant, Organization, optional Team, upstream, and relevant policy/waiver revisions. No decision, metadata, graph context, bundle, recent-allow record, or artifact path may cross those dimensions.
