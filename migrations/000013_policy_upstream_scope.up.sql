ALTER TABLE policies
    ADD COLUMN upstream_id UUID,
    ADD CONSTRAINT fk_policies_upstream_id
        FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE RESTRICT;

ALTER TABLE policy_versions
    ADD COLUMN upstream_id UUID,
    ADD CONSTRAINT fk_policy_versions_upstream_id
        FOREIGN KEY (upstream_id) REFERENCES upstreams(id) ON DELETE RESTRICT;

UPDATE policy_versions pv
SET upstream_id = p.upstream_id
FROM policies p
WHERE p.id = pv.policy_id;

CREATE INDEX idx_policies_tenant_upstream ON policies(tenant_id, upstream_id);
