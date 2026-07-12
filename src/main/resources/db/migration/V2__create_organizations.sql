CREATE TABLE organizations (
    organization_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT organizations_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT organizations_tenant_organization_key
        UNIQUE (tenant_id, organization_id),
    CONSTRAINT organizations_tenant_slug_key
        UNIQUE (tenant_id, slug),
    CONSTRAINT organizations_status_check
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT organizations_version_check
        CHECK (version >= 0),
    CONSTRAINT organizations_slug_check
        CHECK (
            char_length(slug) BETWEEN 1 AND 63
            AND slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'
            AND slug !~ '-$'
        ),
    CONSTRAINT organizations_display_name_check
        CHECK (char_length(btrim(display_name)) BETWEEN 1 AND 200),
    CONSTRAINT organizations_timestamps_check
        CHECK (updated_at >= created_at)
);
