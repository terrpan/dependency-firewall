ALTER TABLE policies
    ADD COLUMN target JSONB;

ALTER TABLE policy_versions
    ADD COLUMN target JSONB;

ALTER TABLE decisions
    ADD COLUMN dependency_context JSONB;

ALTER TABLE evaluations
    ADD COLUMN dependency_context JSONB;

CREATE TABLE dependency_graph_roots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    upstream_id UUID NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    graph_hash TEXT,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    CONSTRAINT dependency_graph_roots_status_check CHECK (status IN ('pending', 'resolving', 'complete', 'failed')),
    UNIQUE (tenant_id, upstream_id, package_name, version)
);

CREATE INDEX idx_dependency_graph_roots_jobs
    ON dependency_graph_roots(status, updated_at);

CREATE TABLE dependency_graph_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    root_id UUID NOT NULL REFERENCES dependency_graph_roots(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL DEFAULT '',
    min_depth INTEGER NOT NULL,
    dependency_types TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (root_id, ecosystem, namespace, name, version, digest)
);

CREATE INDEX idx_dependency_graph_nodes_artifact
    ON dependency_graph_nodes(ecosystem, namespace, name, version, digest);

CREATE TABLE dependency_graph_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    root_id UUID NOT NULL REFERENCES dependency_graph_roots(id) ON DELETE CASCADE,
    parent_node_id UUID NOT NULL REFERENCES dependency_graph_nodes(id) ON DELETE CASCADE,
    child_node_id UUID NOT NULL REFERENCES dependency_graph_nodes(id) ON DELETE CASCADE,
    dependency_type TEXT NOT NULL,
    CONSTRAINT dependency_graph_edges_type_check CHECK (dependency_type IN ('prod', 'dev', 'peer', 'optional')),
    UNIQUE (root_id, parent_node_id, child_node_id, dependency_type)
);

CREATE TABLE dependency_context_summaries (
    root_id UUID NOT NULL REFERENCES dependency_graph_roots(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    upstream_id UUID NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL DEFAULT '',
    context JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (root_id, ecosystem, namespace, name, version, digest)
);

CREATE INDEX idx_dependency_context_summaries_lookup
    ON dependency_context_summaries(tenant_id, upstream_id, ecosystem, namespace, name, version, digest);
