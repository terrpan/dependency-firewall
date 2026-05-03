CREATE INDEX idx_audit_events_tenant_event_type
    ON audit_events(tenant_id, event_type, created_at DESC);

CREATE INDEX idx_audit_events_tenant_correlation
    ON audit_events(tenant_id, ((payload->>'correlation_id')), created_at DESC);

CREATE INDEX idx_audit_events_payload_gin
    ON audit_events
    USING gin (payload jsonb_path_ops);
