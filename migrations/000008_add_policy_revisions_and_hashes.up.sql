CREATE TABLE tenant_policy_revisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    generation BIGINT NOT NULL,
    policy_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, generation)
);

CREATE INDEX idx_tenant_policy_revisions_tenant ON tenant_policy_revisions(tenant_id, generation DESC);

ALTER TABLE decisions
    ADD COLUMN policy_hash TEXT;
