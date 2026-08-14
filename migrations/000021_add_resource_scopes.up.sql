ALTER TABLE policies
    ADD COLUMN scope_kind TEXT,
    ADD COLUMN organization_id UUID,
    ADD COLUMN waiver_mode TEXT;

UPDATE policies
SET scope_kind = 'account',
    waiver_mode = 'none';

ALTER TABLE policies
    ALTER COLUMN scope_kind SET DEFAULT 'account',
    ALTER COLUMN scope_kind SET NOT NULL,
    ALTER COLUMN waiver_mode SET DEFAULT 'none',
    ALTER COLUMN waiver_mode SET NOT NULL;

ALTER TABLE policy_versions
    ADD COLUMN tenant_id UUID,
    ADD COLUMN scope_kind TEXT,
    ADD COLUMN organization_id UUID,
    ADD COLUMN waiver_mode TEXT;

UPDATE policy_versions pv
SET tenant_id = p.tenant_id,
    scope_kind = p.scope_kind,
    organization_id = p.organization_id,
    waiver_mode = p.waiver_mode
FROM policies p
WHERE p.id = pv.policy_id;

ALTER TABLE policy_versions
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN scope_kind SET DEFAULT 'account',
    ALTER COLUMN scope_kind SET NOT NULL,
    ALTER COLUMN waiver_mode SET DEFAULT 'none',
    ALTER COLUMN waiver_mode SET NOT NULL;

ALTER TABLE upstreams
    ADD COLUMN scope_kind TEXT,
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID;

UPDATE upstreams
SET scope_kind = 'tenant_shared';

ALTER TABLE upstreams
    ALTER COLUMN scope_kind SET DEFAULT 'tenant_shared',
    ALTER COLUMN scope_kind SET NOT NULL;

-- Tenants created after 000020 intentionally enter first-Organization onboarding.
-- Only create a compatibility Organization when such a Tenant already owns legacy
-- operational resources that require a deterministic migration scope.
INSERT INTO organizations (tenant_id, name, status, is_default)
SELECT tenant.id,
       'Migration Organization ' || tenant.id::text,
       'active',
       true
FROM tenants tenant
WHERE NOT EXISTS (
          SELECT 1
          FROM organizations organization
          WHERE organization.tenant_id = tenant.id
            AND organization.is_default
      )
  AND (
      EXISTS (SELECT 1 FROM policies policy WHERE policy.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM upstreams upstream WHERE upstream.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM artifacts artifact WHERE artifact.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM proxy_requests request WHERE request.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM evaluations evaluation WHERE evaluation.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM decisions decision WHERE decision.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM audit_events event WHERE event.tenant_id = tenant.id)
      OR EXISTS (SELECT 1 FROM dependency_graph_roots root WHERE root.tenant_id = tenant.id)
  );

ALTER TABLE artifacts
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

ALTER TABLE proxy_requests
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

ALTER TABLE evaluations
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

ALTER TABLE evaluation_reasons
    ADD COLUMN tenant_id UUID,
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

ALTER TABLE decisions
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

ALTER TABLE audit_events
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

UPDATE artifacts resource
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = resource.tenant_id
  AND organization.is_default;

UPDATE proxy_requests resource
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = resource.tenant_id
  AND organization.is_default;

UPDATE evaluations resource
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = resource.tenant_id
  AND organization.is_default;

UPDATE decisions resource
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = resource.tenant_id
  AND organization.is_default;

UPDATE audit_events resource
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = resource.tenant_id
  AND organization.is_default;

UPDATE evaluation_reasons reason
SET tenant_id = evaluation.tenant_id,
    organization_id = evaluation.organization_id,
    team_id = evaluation.team_id,
    upstream_id = evaluation.upstream_id
FROM evaluations evaluation
WHERE evaluation.id = reason.evaluation_id;

ALTER TABLE evaluation_reasons
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE dependency_graph_roots
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID;

UPDATE dependency_graph_roots root
SET organization_id = organization.id
FROM organizations organization
WHERE organization.tenant_id = root.tenant_id
  AND organization.is_default;

ALTER TABLE dependency_graph_nodes
    ADD COLUMN tenant_id UUID,
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

UPDATE dependency_graph_nodes node
SET tenant_id = root.tenant_id,
    organization_id = root.organization_id,
    team_id = root.team_id,
    upstream_id = root.upstream_id
FROM dependency_graph_roots root
WHERE root.id = node.root_id;

ALTER TABLE dependency_graph_nodes
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN upstream_id SET NOT NULL;

ALTER TABLE dependency_graph_edges
    ADD COLUMN tenant_id UUID,
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID,
    ADD COLUMN upstream_id UUID;

UPDATE dependency_graph_edges edge
SET tenant_id = root.tenant_id,
    organization_id = root.organization_id,
    team_id = root.team_id,
    upstream_id = root.upstream_id
FROM dependency_graph_roots root
WHERE root.id = edge.root_id;

ALTER TABLE dependency_graph_edges
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN upstream_id SET NOT NULL;

ALTER TABLE dependency_context_summaries
    ADD COLUMN organization_id UUID,
    ADD COLUMN team_id UUID;

UPDATE dependency_context_summaries summary
SET organization_id = root.organization_id,
    team_id = root.team_id
FROM dependency_graph_roots root
WHERE root.id = summary.root_id;
