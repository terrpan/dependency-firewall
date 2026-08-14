ALTER TABLE dependency_context_summaries
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE dependency_graph_edges
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE dependency_graph_nodes
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE dependency_graph_roots
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE audit_events
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE decisions
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE evaluation_reasons
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE evaluations
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE proxy_requests
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE artifacts
    DROP COLUMN IF EXISTS upstream_id,
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id;

ALTER TABLE upstreams
    DROP COLUMN IF EXISTS team_id,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS scope_kind;

ALTER TABLE policy_versions
    DROP COLUMN IF EXISTS waiver_mode,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS scope_kind,
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE policies
    DROP COLUMN IF EXISTS waiver_mode,
    DROP COLUMN IF EXISTS organization_id,
    DROP COLUMN IF EXISTS scope_kind;

DELETE FROM organizations
WHERE is_default
  AND name = 'Migration Organization ' || tenant_id::text;
