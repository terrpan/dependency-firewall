DROP INDEX IF EXISTS idx_policies_tenant_upstream;

ALTER TABLE policy_versions
    DROP CONSTRAINT fk_policy_versions_upstream_id,
    DROP COLUMN upstream_id;

ALTER TABLE policies
    DROP CONSTRAINT fk_policies_upstream_id,
    DROP COLUMN upstream_id;
