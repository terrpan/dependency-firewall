CREATE TABLE artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, ecosystem, namespace, name, version, digest)
);

CREATE INDEX idx_artifacts_tenant ON artifacts(tenant_id);
CREATE INDEX idx_artifacts_lookup ON artifacts(tenant_id, ecosystem, namespace, name);
