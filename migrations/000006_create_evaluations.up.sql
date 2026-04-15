CREATE TABLE proxy_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_id UUID REFERENCES artifacts(id),
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    remote_addr TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_proxy_requests_tenant ON proxy_requests(tenant_id, created_at DESC);

CREATE TABLE evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_id UUID REFERENCES artifacts(id),
    outcome TEXT NOT NULL,
    policy_id UUID REFERENCES policies(id),
    reason TEXT,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evaluations_tenant ON evaluations(tenant_id, evaluated_at DESC);

CREATE TABLE evaluation_reasons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evaluation_id UUID NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id),
    policy_name TEXT,
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE TABLE decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    artifact_id UUID REFERENCES artifacts(id),
    outcome TEXT NOT NULL,
    policy_id UUID REFERENCES policies(id),
    reason TEXT,
    cached_at TIMESTAMPTZ,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_decisions_tenant ON decisions(tenant_id, evaluated_at DESC);
CREATE INDEX idx_decisions_artifact ON decisions(tenant_id, artifact_id);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    entity_type TEXT,
    entity_id UUID,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_tenant ON audit_events(tenant_id, created_at DESC);
