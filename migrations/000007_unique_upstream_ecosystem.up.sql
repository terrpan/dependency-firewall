ALTER TABLE upstreams ADD CONSTRAINT uq_upstreams_tenant_ecosystem UNIQUE (tenant_id, ecosystem);
