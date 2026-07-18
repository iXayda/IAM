CREATE TABLE groups (
    group_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT groups_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT groups_tenant_group_key
        UNIQUE (tenant_id, group_id),
    CONSTRAINT groups_status_check
        CHECK (status IN ('active', 'deleted')),
    CONSTRAINT groups_version_check
        CHECK (version >= 0),
    CONSTRAINT groups_display_name_check
        CHECK (
            display_name !~ '^[[:space:]]|[[:space:]]$'
            AND char_length(display_name) BETWEEN 1 AND 200
            AND display_name !~ '[[:cntrl:]]'
        ),
    CONSTRAINT groups_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE INDEX groups_active_tenant_id_idx
    ON groups (tenant_id, group_id)
    WHERE status = 'active';
