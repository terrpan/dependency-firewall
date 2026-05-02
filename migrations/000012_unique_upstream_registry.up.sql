ALTER TABLE upstreams DROP CONSTRAINT uq_upstreams_tenant_ecosystem;
ALTER TABLE upstreams ADD CONSTRAINT uq_upstreams_tenant_ecosystem_base_url UNIQUE (tenant_id, ecosystem, base_url);
