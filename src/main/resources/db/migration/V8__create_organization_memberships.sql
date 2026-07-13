CREATE TABLE organization_memberships (
    tenant_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT organization_memberships_pkey
        PRIMARY KEY (tenant_id, organization_id, user_id),
    CONSTRAINT organization_memberships_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES organizations (tenant_id, organization_id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT organization_memberships_status_check
        CHECK (status IN ('active', 'removed')),
    CONSTRAINT organization_memberships_version_check
        CHECK (version >= 0),
    CONSTRAINT organization_memberships_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE INDEX organization_memberships_user_status_organization_idx
    ON organization_memberships (tenant_id, user_id, status, organization_id);
