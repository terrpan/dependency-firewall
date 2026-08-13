CREATE TABLE tenant_identity_links (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider),
    CONSTRAINT tenant_identity_links_provider_external_key UNIQUE (provider, external_id),
    CONSTRAINT tenant_identity_links_provider_check CHECK (length(btrim(provider)) > 0),
    CONSTRAINT tenant_identity_links_external_id_check CHECK (length(btrim(external_id)) > 0)
);

CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT principals_status_check CHECK (status IN ('active', 'suspended', 'deactivated'))
);

CREATE TABLE principal_identities (
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    external_subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, external_subject),
    CONSTRAINT principal_identities_principal_provider_key UNIQUE (principal_id, provider),
    CONSTRAINT principal_identities_provider_check CHECK (length(btrim(provider)) > 0),
    CONSTRAINT principal_identities_external_subject_check CHECK (length(btrim(external_subject)) > 0)
);

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT organizations_status_check CHECK (status IN ('active', 'archived')),
    CONSTRAINT organizations_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT organizations_tenant_name_key UNIQUE (tenant_id, name)
);

CREATE UNIQUE INDEX organizations_one_default_per_tenant
    ON organizations (tenant_id)
    WHERE is_default;

CREATE INDEX organizations_tenant_status_name_idx
    ON organizations (tenant_id, status, name);

CREATE TABLE organization_memberships (
    tenant_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, principal_id),
    CONSTRAINT organization_memberships_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT organization_memberships_role_check
        CHECK (role IN ('admin', 'policy_manager', 'operator', 'viewer'))
);

CREATE INDEX organization_memberships_tenant_principal_idx
    ON organization_memberships (tenant_id, principal_id, organization_id);

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    name TEXT NOT NULL,
    archived_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT teams_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT teams_tenant_organization_id_key UNIQUE (tenant_id, organization_id, id),
    CONSTRAINT teams_organization_name_key UNIQUE (organization_id, name)
);

CREATE INDEX teams_tenant_organization_active_idx
    ON teams (tenant_id, organization_id, name)
    WHERE archived_at IS NULL;

CREATE TABLE team_memberships (
    tenant_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    team_id UUID NOT NULL,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, principal_id),
    CONSTRAINT team_memberships_team_fk
        FOREIGN KEY (tenant_id, organization_id, team_id)
        REFERENCES teams(tenant_id, organization_id, id) ON DELETE CASCADE
);

CREATE INDEX team_memberships_tenant_organization_principal_idx
    ON team_memberships (tenant_id, organization_id, principal_id, team_id);

INSERT INTO principals (id, display_name, email, status, created_at, updated_at)
SELECT id, name, email, 'active', created_at, created_at
FROM users
ON CONFLICT (id) DO NOTHING;

INSERT INTO organizations (tenant_id, name, status, is_default)
SELECT id, 'Default Organization', 'active', true
FROM tenants;
