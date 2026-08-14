ALTER TABLE policies
    ADD CONSTRAINT policies_tenant_id_id_key UNIQUE (tenant_id, id),
    DROP CONSTRAINT policies_tenant_id_name_key,
    ADD CONSTRAINT policies_tenant_id_name_key
        UNIQUE NULLS NOT DISTINCT (tenant_id, scope_kind, organization_id, name);

ALTER TABLE upstreams
    ADD CONSTRAINT upstreams_tenant_id_id_key UNIQUE (tenant_id, id),
    DROP CONSTRAINT upstreams_tenant_id_name_key,
    ADD CONSTRAINT upstreams_tenant_id_name_key
        UNIQUE NULLS NOT DISTINCT (tenant_id, scope_kind, organization_id, team_id, name),
    DROP CONSTRAINT uq_upstreams_tenant_ecosystem_base_url,
    ADD CONSTRAINT uq_upstreams_tenant_ecosystem_base_url
        UNIQUE NULLS NOT DISTINCT (tenant_id, scope_kind, organization_id, team_id, ecosystem, base_url);

DO $migration$
DECLARE
    legacy_constraint TEXT;
BEGIN
    SELECT constraint_row.conname
    INTO legacy_constraint
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'artifacts'::regclass
      AND constraint_row.contype = 'u'
      AND pg_get_constraintdef(constraint_row.oid) =
          'UNIQUE (tenant_id, ecosystem, namespace, name, version, digest)';

    IF legacy_constraint IS NULL THEN
        RAISE EXCEPTION 'legacy artifact identity constraint was not found';
    END IF;

    EXECUTE format('ALTER TABLE artifacts DROP CONSTRAINT %I', legacy_constraint);
END
$migration$;

ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_tenant_id_id_key UNIQUE (tenant_id, id),
    ADD CONSTRAINT artifacts_tenant_organization_id_id_key UNIQUE (tenant_id, organization_id, id),
    ADD CONSTRAINT artifacts_tenant_organization_team_id_id_key UNIQUE (tenant_id, organization_id, team_id, id),
    ADD CONSTRAINT artifacts_scope_identity_key
        UNIQUE NULLS NOT DISTINCT (
            tenant_id, organization_id, team_id, upstream_id,
            ecosystem, namespace, name, version, digest
        );

ALTER TABLE evaluations
    ADD CONSTRAINT evaluations_tenant_id_id_key UNIQUE (tenant_id, id),
    ADD CONSTRAINT evaluations_tenant_organization_id_id_key UNIQUE (tenant_id, organization_id, id),
    ADD CONSTRAINT evaluations_tenant_organization_team_id_id_key UNIQUE (tenant_id, organization_id, team_id, id);

DO $migration$
DECLARE
    legacy_constraint TEXT;
BEGIN
    SELECT constraint_row.conname
    INTO legacy_constraint
    FROM pg_constraint constraint_row
    WHERE constraint_row.conrelid = 'dependency_graph_roots'::regclass
      AND constraint_row.contype = 'u'
      AND pg_get_constraintdef(constraint_row.oid) =
          'UNIQUE (tenant_id, upstream_id, package_name, version)';

    IF legacy_constraint IS NULL THEN
        RAISE EXCEPTION 'legacy dependency graph root identity constraint was not found';
    END IF;

    EXECUTE format('ALTER TABLE dependency_graph_roots DROP CONSTRAINT %I', legacy_constraint);
END
$migration$;

ALTER TABLE dependency_graph_roots
    ADD CONSTRAINT dependency_graph_roots_tenant_id_id_key UNIQUE (tenant_id, id),
    ADD CONSTRAINT dependency_graph_roots_tenant_org_id_id_key UNIQUE (tenant_id, organization_id, id),
    ADD CONSTRAINT dependency_graph_roots_tenant_org_team_id_id_key UNIQUE (tenant_id, organization_id, team_id, id),
    ADD CONSTRAINT dependency_graph_roots_scope_identity_key
        UNIQUE NULLS NOT DISTINCT (
            tenant_id, organization_id, team_id, upstream_id, package_name, version
        );

ALTER TABLE dependency_graph_nodes
    ADD CONSTRAINT dependency_graph_nodes_tenant_root_id_id_key UNIQUE (tenant_id, root_id, id);

ALTER TABLE policies
    ADD CONSTRAINT policies_scope_shape_check
        CHECK (
            (scope_kind = 'account' AND organization_id IS NULL)
            OR (scope_kind = 'organization' AND organization_id IS NOT NULL)
        ) NOT VALID,
    ADD CONSTRAINT policies_waiver_mode_check
        CHECK (waiver_mode IN ('none', 'approval_required')) NOT VALID,
    ADD CONSTRAINT policies_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT policies_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE policy_versions
    ADD CONSTRAINT policy_versions_scope_shape_check
        CHECK (
            (scope_kind = 'account' AND organization_id IS NULL)
            OR (scope_kind = 'organization' AND organization_id IS NOT NULL)
        ) NOT VALID,
    ADD CONSTRAINT policy_versions_waiver_mode_check
        CHECK (waiver_mode IN ('none', 'approval_required')) NOT VALID,
    ADD CONSTRAINT policy_versions_policy_tenant_fk
        FOREIGN KEY (tenant_id, policy_id)
        REFERENCES policies(tenant_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT policy_versions_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT policy_versions_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE upstreams
    ADD CONSTRAINT upstreams_scope_shape_check
        CHECK (
            (scope_kind = 'tenant_shared' AND organization_id IS NULL AND team_id IS NULL)
            OR (scope_kind = 'organization_shared' AND organization_id IS NOT NULL AND team_id IS NULL)
            OR (scope_kind = 'team_local' AND organization_id IS NOT NULL AND team_id IS NOT NULL)
        ) NOT VALID,
    ADD CONSTRAINT upstreams_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT upstreams_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT artifacts_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT artifacts_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT artifacts_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE proxy_requests
    ADD CONSTRAINT proxy_requests_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT proxy_requests_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT proxy_requests_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT proxy_requests_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT proxy_requests_artifact_scope_fk
        FOREIGN KEY (tenant_id, organization_id, artifact_id)
        REFERENCES artifacts(tenant_id, organization_id, id) NOT VALID;

ALTER TABLE evaluations
    ADD CONSTRAINT evaluations_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT evaluations_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT evaluations_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT evaluations_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT evaluations_artifact_scope_fk
        FOREIGN KEY (tenant_id, organization_id, artifact_id)
        REFERENCES artifacts(tenant_id, organization_id, id) NOT VALID,
    ADD CONSTRAINT evaluations_policy_tenant_fk
        FOREIGN KEY (tenant_id, policy_id)
        REFERENCES policies(tenant_id, id) NOT VALID;

ALTER TABLE evaluation_reasons
    ADD CONSTRAINT evaluation_reasons_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT evaluation_reasons_evaluation_tenant_fk
        FOREIGN KEY (tenant_id, evaluation_id)
        REFERENCES evaluations(tenant_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT evaluation_reasons_evaluation_scope_fk
        FOREIGN KEY (tenant_id, organization_id, evaluation_id)
        REFERENCES evaluations(tenant_id, organization_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT evaluation_reasons_evaluation_team_scope_fk
        FOREIGN KEY (tenant_id, organization_id, team_id, evaluation_id)
        REFERENCES evaluations(tenant_id, organization_id, team_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT evaluation_reasons_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT evaluation_reasons_policy_tenant_fk
        FOREIGN KEY (tenant_id, policy_id)
        REFERENCES policies(tenant_id, id) NOT VALID;

ALTER TABLE decisions
    ADD CONSTRAINT decisions_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT decisions_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT decisions_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT decisions_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT decisions_artifact_scope_fk
        FOREIGN KEY (tenant_id, organization_id, artifact_id)
        REFERENCES artifacts(tenant_id, organization_id, id) NOT VALID,
    ADD CONSTRAINT decisions_policy_tenant_fk
        FOREIGN KEY (tenant_id, policy_id)
        REFERENCES policies(tenant_id, id) NOT VALID;

ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT audit_events_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT audit_events_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT audit_events_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE RESTRICT NOT VALID;

ALTER TABLE dependency_graph_roots
    ADD CONSTRAINT dependency_graph_roots_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT dependency_graph_roots_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT dependency_graph_roots_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT dependency_graph_roots_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE CASCADE NOT VALID;

ALTER TABLE dependency_graph_nodes
    ADD CONSTRAINT dependency_graph_nodes_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT dependency_graph_nodes_root_tenant_fk
        FOREIGN KEY (tenant_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_nodes_root_scope_fk
        FOREIGN KEY (tenant_id, organization_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_nodes_root_team_scope_fk
        FOREIGN KEY (tenant_id, organization_id, team_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, team_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_nodes_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE CASCADE NOT VALID;

ALTER TABLE dependency_graph_edges
    ADD CONSTRAINT dependency_graph_edges_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_root_tenant_fk
        FOREIGN KEY (tenant_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_root_scope_fk
        FOREIGN KEY (tenant_id, organization_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_root_team_scope_fk
        FOREIGN KEY (tenant_id, organization_id, team_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, team_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_parent_node_tenant_fk
        FOREIGN KEY (tenant_id, root_id, parent_node_id)
        REFERENCES dependency_graph_nodes(tenant_id, root_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_child_node_tenant_fk
        FOREIGN KEY (tenant_id, root_id, child_node_id)
        REFERENCES dependency_graph_nodes(tenant_id, root_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_graph_edges_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE CASCADE NOT VALID;

ALTER TABLE dependency_context_summaries
    ADD CONSTRAINT dependency_context_team_requires_organization_check
        CHECK (team_id IS NULL OR organization_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT dependency_context_root_tenant_fk
        FOREIGN KEY (tenant_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_context_root_scope_fk
        FOREIGN KEY (tenant_id, organization_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_context_root_team_scope_fk
        FOREIGN KEY (tenant_id, organization_id, team_id, root_id)
        REFERENCES dependency_graph_roots(tenant_id, organization_id, team_id, id) ON DELETE CASCADE NOT VALID,
    ADD CONSTRAINT dependency_context_upstream_tenant_fk
        FOREIGN KEY (tenant_id, upstream_id)
        REFERENCES upstreams(tenant_id, id) ON DELETE CASCADE NOT VALID;

ALTER TABLE policies VALIDATE CONSTRAINT policies_scope_shape_check;
ALTER TABLE policies VALIDATE CONSTRAINT policies_waiver_mode_check;
ALTER TABLE policies VALIDATE CONSTRAINT policies_organization_fk;
ALTER TABLE policies VALIDATE CONSTRAINT policies_upstream_tenant_fk;
ALTER TABLE policy_versions VALIDATE CONSTRAINT policy_versions_scope_shape_check;
ALTER TABLE policy_versions VALIDATE CONSTRAINT policy_versions_waiver_mode_check;
ALTER TABLE policy_versions VALIDATE CONSTRAINT policy_versions_policy_tenant_fk;
ALTER TABLE policy_versions VALIDATE CONSTRAINT policy_versions_organization_fk;
ALTER TABLE policy_versions VALIDATE CONSTRAINT policy_versions_upstream_tenant_fk;
ALTER TABLE upstreams VALIDATE CONSTRAINT upstreams_scope_shape_check;
ALTER TABLE upstreams VALIDATE CONSTRAINT upstreams_organization_fk;
ALTER TABLE upstreams VALIDATE CONSTRAINT upstreams_team_fk;
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_team_requires_organization_check;
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_organization_fk;
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_team_fk;
ALTER TABLE artifacts VALIDATE CONSTRAINT artifacts_upstream_tenant_fk;
ALTER TABLE proxy_requests VALIDATE CONSTRAINT proxy_requests_team_requires_organization_check;
ALTER TABLE proxy_requests VALIDATE CONSTRAINT proxy_requests_organization_fk;
ALTER TABLE proxy_requests VALIDATE CONSTRAINT proxy_requests_team_fk;
ALTER TABLE proxy_requests VALIDATE CONSTRAINT proxy_requests_upstream_tenant_fk;
ALTER TABLE proxy_requests VALIDATE CONSTRAINT proxy_requests_artifact_scope_fk;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_team_requires_organization_check;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_organization_fk;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_team_fk;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_upstream_tenant_fk;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_artifact_scope_fk;
ALTER TABLE evaluations VALIDATE CONSTRAINT evaluations_policy_tenant_fk;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_team_requires_organization_check;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_evaluation_tenant_fk;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_evaluation_scope_fk;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_evaluation_team_scope_fk;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_upstream_tenant_fk;
ALTER TABLE evaluation_reasons VALIDATE CONSTRAINT evaluation_reasons_policy_tenant_fk;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_team_requires_organization_check;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_organization_fk;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_team_fk;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_upstream_tenant_fk;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_artifact_scope_fk;
ALTER TABLE decisions VALIDATE CONSTRAINT decisions_policy_tenant_fk;
ALTER TABLE audit_events VALIDATE CONSTRAINT audit_events_team_requires_organization_check;
ALTER TABLE audit_events VALIDATE CONSTRAINT audit_events_organization_fk;
ALTER TABLE audit_events VALIDATE CONSTRAINT audit_events_team_fk;
ALTER TABLE audit_events VALIDATE CONSTRAINT audit_events_upstream_tenant_fk;
ALTER TABLE dependency_graph_roots VALIDATE CONSTRAINT dependency_graph_roots_team_requires_organization_check;
ALTER TABLE dependency_graph_roots VALIDATE CONSTRAINT dependency_graph_roots_organization_fk;
ALTER TABLE dependency_graph_roots VALIDATE CONSTRAINT dependency_graph_roots_team_fk;
ALTER TABLE dependency_graph_roots VALIDATE CONSTRAINT dependency_graph_roots_upstream_tenant_fk;
ALTER TABLE dependency_graph_nodes VALIDATE CONSTRAINT dependency_graph_nodes_team_requires_organization_check;
ALTER TABLE dependency_graph_nodes VALIDATE CONSTRAINT dependency_graph_nodes_root_tenant_fk;
ALTER TABLE dependency_graph_nodes VALIDATE CONSTRAINT dependency_graph_nodes_root_scope_fk;
ALTER TABLE dependency_graph_nodes VALIDATE CONSTRAINT dependency_graph_nodes_root_team_scope_fk;
ALTER TABLE dependency_graph_nodes VALIDATE CONSTRAINT dependency_graph_nodes_upstream_tenant_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_team_requires_organization_check;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_root_tenant_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_root_scope_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_root_team_scope_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_parent_node_tenant_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_child_node_tenant_fk;
ALTER TABLE dependency_graph_edges VALIDATE CONSTRAINT dependency_graph_edges_upstream_tenant_fk;
ALTER TABLE dependency_context_summaries VALIDATE CONSTRAINT dependency_context_team_requires_organization_check;
ALTER TABLE dependency_context_summaries VALIDATE CONSTRAINT dependency_context_root_tenant_fk;
ALTER TABLE dependency_context_summaries VALIDATE CONSTRAINT dependency_context_root_scope_fk;
ALTER TABLE dependency_context_summaries VALIDATE CONSTRAINT dependency_context_root_team_scope_fk;
ALTER TABLE dependency_context_summaries VALIDATE CONSTRAINT dependency_context_upstream_tenant_fk;

CREATE INDEX policies_tenant_scope_priority_idx
    ON policies (tenant_id, scope_kind, organization_id, priority);

CREATE INDEX upstreams_tenant_scope_ecosystem_idx
    ON upstreams (tenant_id, scope_kind, organization_id, team_id, ecosystem);

CREATE INDEX artifacts_tenant_scope_lookup_idx
    ON artifacts (tenant_id, organization_id, team_id, upstream_id, ecosystem, namespace, name);

CREATE INDEX proxy_requests_tenant_scope_created_idx
    ON proxy_requests (tenant_id, organization_id, team_id, upstream_id, created_at DESC);

CREATE INDEX evaluations_tenant_scope_evaluated_idx
    ON evaluations (tenant_id, organization_id, team_id, upstream_id, evaluated_at DESC);

CREATE INDEX decisions_tenant_scope_evaluated_idx
    ON decisions (tenant_id, organization_id, team_id, upstream_id, evaluated_at DESC);

CREATE INDEX audit_events_tenant_scope_created_idx
    ON audit_events (tenant_id, organization_id, team_id, created_at DESC);

CREATE INDEX dependency_graph_roots_tenant_scope_updated_idx
    ON dependency_graph_roots (tenant_id, organization_id, team_id, upstream_id, updated_at DESC);

CREATE INDEX dependency_graph_nodes_tenant_scope_artifact_idx
    ON dependency_graph_nodes (tenant_id, organization_id, team_id, upstream_id, ecosystem, namespace, name, version, digest);

CREATE INDEX dependency_graph_edges_tenant_scope_root_idx
    ON dependency_graph_edges (tenant_id, organization_id, team_id, upstream_id, root_id);

CREATE INDEX dependency_context_tenant_scope_lookup_idx
    ON dependency_context_summaries (tenant_id, organization_id, team_id, upstream_id, ecosystem, namespace, name, version, digest);
