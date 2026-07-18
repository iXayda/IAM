CREATE TABLE group_memberships (
    tenant_id UUID NOT NULL,
    group_id UUID NOT NULL,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT group_memberships_pkey
        PRIMARY KEY (tenant_id, group_id, user_id),
    CONSTRAINT group_memberships_group_fk
        FOREIGN KEY (tenant_id, group_id)
        REFERENCES groups (tenant_id, group_id) ON DELETE RESTRICT,
    CONSTRAINT group_memberships_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX group_memberships_user_group_idx
    ON group_memberships (tenant_id, user_id, group_id);
