DROP TABLE IF EXISTS dependency_context_summaries;
DROP TABLE IF EXISTS dependency_graph_edges;
DROP TABLE IF EXISTS dependency_graph_nodes;
DROP TABLE IF EXISTS dependency_graph_roots;

ALTER TABLE evaluations
    DROP COLUMN IF EXISTS dependency_context;

ALTER TABLE decisions
    DROP COLUMN IF EXISTS dependency_context;

ALTER TABLE policy_versions
    DROP COLUMN IF EXISTS target;

ALTER TABLE policies
    DROP COLUMN IF EXISTS target;
