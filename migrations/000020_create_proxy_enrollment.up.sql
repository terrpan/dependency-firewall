CREATE TABLE proxy_installations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(btrim(name)) > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_connected_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (id, tenant_id)
);

CREATE UNIQUE INDEX proxy_installations_live_name_key
    ON proxy_installations (tenant_id, lower(name))
    WHERE status IN ('pending', 'active');

CREATE TABLE workload_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    installation_id UUID NOT NULL,
    canonical_identity TEXT NOT NULL UNIQUE,
    certificate_serial TEXT NOT NULL,
    certificate_not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (id, tenant_id),
    FOREIGN KEY (installation_id, tenant_id)
        REFERENCES proxy_installations(id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX workload_identities_installation_idx
    ON workload_identities (tenant_id, installation_id);

CREATE TABLE proxy_enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_credential_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(device_credential_digest) = 32),
    user_code_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(user_code_digest) = 32),
    csr_der BYTEA NOT NULL CHECK (octet_length(csr_der) > 0),
    proposed_name TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
    expires_at TIMESTAMPTZ NOT NULL,
    poll_interval_seconds INTEGER NOT NULL CHECK (poll_interval_seconds > 0),
    next_poll_at TIMESTAMPTZ NOT NULL,
    tenant_id UUID,
    installation_id UUID,
    identity_id UUID,
    canonical_identity TEXT,
    certificate_chain_pem BYTEA,
    server_trust_bundle_pem BYTEA,
    approving_principal_id TEXT,
    denying_principal_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    denied_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    expired_at TIMESTAMPTZ,
    FOREIGN KEY (installation_id, tenant_id)
        REFERENCES proxy_installations(id, tenant_id),
    FOREIGN KEY (identity_id, tenant_id)
        REFERENCES workload_identities(id, tenant_id),
    CHECK ((tenant_id IS NULL) = (installation_id IS NULL)),
    CHECK ((tenant_id IS NULL) = (identity_id IS NULL))
);

CREATE INDEX proxy_enrollments_expires_idx ON proxy_enrollments (expires_at)
    WHERE status IN ('pending', 'approved');
