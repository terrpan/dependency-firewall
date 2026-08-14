DROP INDEX IF EXISTS dependency_context_tenant_scope_lookup_idx;
DROP INDEX IF EXISTS dependency_graph_edges_tenant_scope_root_idx;
DROP INDEX IF EXISTS dependency_graph_nodes_tenant_scope_artifact_idx;
DROP INDEX IF EXISTS dependency_graph_roots_tenant_scope_updated_idx;
DROP INDEX IF EXISTS audit_events_tenant_scope_created_idx;
DROP INDEX IF EXISTS decisions_tenant_scope_evaluated_idx;
DROP INDEX IF EXISTS evaluations_tenant_scope_evaluated_idx;
DROP INDEX IF EXISTS proxy_requests_tenant_scope_created_idx;
DROP INDEX IF EXISTS artifacts_tenant_scope_lookup_idx;
DROP INDEX IF EXISTS upstreams_tenant_scope_ecosystem_idx;
DROP INDEX IF EXISTS policies_tenant_scope_priority_idx;

ALTER TABLE dependency_context_summaries
    DROP CONSTRAINT IF EXISTS dependency_context_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_context_root_team_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_context_root_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_context_root_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_context_team_requires_organization_check;

ALTER TABLE dependency_graph_edges
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_child_node_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_parent_node_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_root_team_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_root_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_root_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_edges_team_requires_organization_check;

ALTER TABLE dependency_graph_nodes
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_root_team_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_root_scope_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_root_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_team_requires_organization_check;

ALTER TABLE dependency_graph_roots
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_team_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_organization_fk,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_team_requires_organization_check;

ALTER TABLE audit_events
    DROP CONSTRAINT IF EXISTS audit_events_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS audit_events_team_fk,
    DROP CONSTRAINT IF EXISTS audit_events_organization_fk,
    DROP CONSTRAINT IF EXISTS audit_events_team_requires_organization_check;

ALTER TABLE decisions
    DROP CONSTRAINT IF EXISTS decisions_policy_tenant_fk,
    DROP CONSTRAINT IF EXISTS decisions_artifact_scope_fk,
    DROP CONSTRAINT IF EXISTS decisions_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS decisions_team_fk,
    DROP CONSTRAINT IF EXISTS decisions_organization_fk,
    DROP CONSTRAINT IF EXISTS decisions_team_requires_organization_check;

ALTER TABLE evaluation_reasons
    DROP CONSTRAINT IF EXISTS evaluation_reasons_policy_tenant_fk,
    DROP CONSTRAINT IF EXISTS evaluation_reasons_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS evaluation_reasons_evaluation_team_scope_fk,
    DROP CONSTRAINT IF EXISTS evaluation_reasons_evaluation_scope_fk,
    DROP CONSTRAINT IF EXISTS evaluation_reasons_evaluation_tenant_fk,
    DROP CONSTRAINT IF EXISTS evaluation_reasons_team_requires_organization_check;

ALTER TABLE evaluations
    DROP CONSTRAINT IF EXISTS evaluations_policy_tenant_fk,
    DROP CONSTRAINT IF EXISTS evaluations_artifact_scope_fk,
    DROP CONSTRAINT IF EXISTS evaluations_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS evaluations_team_fk,
    DROP CONSTRAINT IF EXISTS evaluations_organization_fk,
    DROP CONSTRAINT IF EXISTS evaluations_team_requires_organization_check;

ALTER TABLE proxy_requests
    DROP CONSTRAINT IF EXISTS proxy_requests_artifact_scope_fk,
    DROP CONSTRAINT IF EXISTS proxy_requests_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS proxy_requests_team_fk,
    DROP CONSTRAINT IF EXISTS proxy_requests_organization_fk,
    DROP CONSTRAINT IF EXISTS proxy_requests_team_requires_organization_check;

ALTER TABLE artifacts
    DROP CONSTRAINT IF EXISTS artifacts_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS artifacts_team_fk,
    DROP CONSTRAINT IF EXISTS artifacts_organization_fk,
    DROP CONSTRAINT IF EXISTS artifacts_team_requires_organization_check;

ALTER TABLE policy_versions
    DROP CONSTRAINT IF EXISTS policy_versions_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS policy_versions_organization_fk,
    DROP CONSTRAINT IF EXISTS policy_versions_policy_tenant_fk,
    DROP CONSTRAINT IF EXISTS policy_versions_waiver_mode_check,
    DROP CONSTRAINT IF EXISTS policy_versions_scope_shape_check;

ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_upstream_tenant_fk,
    DROP CONSTRAINT IF EXISTS policies_organization_fk,
    DROP CONSTRAINT IF EXISTS policies_waiver_mode_check,
    DROP CONSTRAINT IF EXISTS policies_scope_shape_check;

ALTER TABLE upstreams
    DROP CONSTRAINT IF EXISTS upstreams_team_fk,
    DROP CONSTRAINT IF EXISTS upstreams_organization_fk,
    DROP CONSTRAINT IF EXISTS upstreams_scope_shape_check;

ALTER TABLE dependency_graph_nodes
    DROP CONSTRAINT IF EXISTS dependency_graph_nodes_tenant_root_id_id_key;

ALTER TABLE dependency_graph_roots
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_tenant_org_team_id_id_key,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_tenant_org_id_id_key,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_tenant_id_id_key,
    DROP CONSTRAINT IF EXISTS dependency_graph_roots_scope_identity_key,
    ADD CONSTRAINT dependency_graph_roots_tenant_id_upstream_id_package_name_version_key
        UNIQUE (tenant_id, upstream_id, package_name, version);

ALTER TABLE evaluations
    DROP CONSTRAINT IF EXISTS evaluations_tenant_organization_team_id_id_key,
    DROP CONSTRAINT IF EXISTS evaluations_tenant_organization_id_id_key,
    DROP CONSTRAINT IF EXISTS evaluations_tenant_id_id_key;

ALTER TABLE artifacts
    DROP CONSTRAINT IF EXISTS artifacts_tenant_organization_team_id_id_key,
    DROP CONSTRAINT IF EXISTS artifacts_tenant_organization_id_id_key,
    DROP CONSTRAINT IF EXISTS artifacts_tenant_id_id_key,
    DROP CONSTRAINT IF EXISTS artifacts_scope_identity_key,
    ADD CONSTRAINT artifacts_tenant_id_ecosystem_namespace_name_version_digest_key
        UNIQUE (tenant_id, ecosystem, namespace, name, version, digest);

ALTER TABLE upstreams
    DROP CONSTRAINT IF EXISTS upstreams_tenant_id_id_key,
    DROP CONSTRAINT upstreams_tenant_id_name_key,
    ADD CONSTRAINT upstreams_tenant_id_name_key UNIQUE (tenant_id, name),
    DROP CONSTRAINT uq_upstreams_tenant_ecosystem_base_url,
    ADD CONSTRAINT uq_upstreams_tenant_ecosystem_base_url UNIQUE (tenant_id, ecosystem, base_url);

ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_tenant_id_id_key,
    DROP CONSTRAINT policies_tenant_id_name_key,
    ADD CONSTRAINT policies_tenant_id_name_key UNIQUE (tenant_id, name);
