CREATE TABLE data_plane_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    team_id UUID,
    name TEXT NOT NULL,
    secret_digest TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES principals(id),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT data_plane_credentials_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT data_plane_credentials_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE CASCADE,
    CONSTRAINT data_plane_credentials_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT data_plane_credentials_digest_check CHECK (length(secret_digest) = 64),
    CONSTRAINT data_plane_credentials_scope_check CHECK (team_id IS NULL OR organization_id IS NOT NULL)
);

CREATE INDEX data_plane_credentials_tenant_scope_idx
    ON data_plane_credentials (tenant_id, organization_id, team_id);
CREATE UNIQUE INDEX data_plane_credentials_digest_key
    ON data_plane_credentials (secret_digest);
CREATE UNIQUE INDEX data_plane_credentials_name_key
    ON data_plane_credentials (tenant_id, organization_id, team_id, name) NULLS NOT DISTINCT;
