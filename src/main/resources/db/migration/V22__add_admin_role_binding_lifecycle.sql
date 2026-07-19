ALTER TABLE admin_role_bindings
    ADD COLUMN binding_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN revoked_by_user_id UUID,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    DROP CONSTRAINT admin_role_bindings_pkey,
    ADD CONSTRAINT admin_role_bindings_pkey
        PRIMARY KEY (binding_id),
    ADD CONSTRAINT admin_role_bindings_status_check
        CHECK (status IN ('active', 'revoked')),
    ADD CONSTRAINT admin_role_bindings_version_check
        CHECK (version >= 0),
    ADD CONSTRAINT admin_role_bindings_revoker_fk
        FOREIGN KEY (tenant_id, revoked_by_user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT admin_role_bindings_revocation_check
        CHECK (
            (status = 'active' AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
            OR (
                status = 'revoked'
                AND revoked_by_user_id IS NOT NULL
                AND revoked_at IS NOT NULL
                AND revoked_at >= created_at
                AND revoked_at = updated_at
            )
        ),
    ADD CONSTRAINT admin_role_bindings_no_self_revoke_check
        CHECK (revoked_by_user_id IS NULL OR revoked_by_user_id <> user_id);

CREATE UNIQUE INDEX admin_role_bindings_active_role_key
    ON admin_role_bindings (tenant_id, user_id, role_code)
    WHERE status = 'active';

CREATE INDEX admin_role_bindings_revoker_idx
    ON admin_role_bindings (tenant_id, revoked_by_user_id)
    WHERE revoked_by_user_id IS NOT NULL;
