ALTER TABLE upstreams DROP CONSTRAINT uq_upstreams_tenant_ecosystem_base_url;
ALTER TABLE upstreams ADD CONSTRAINT uq_upstreams_tenant_ecosystem UNIQUE (tenant_id, ecosystem);
