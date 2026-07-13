CREATE TABLE user_sessions (
    tenant_id UUID NOT NULL,
    session_id UUID NOT NULL,
    user_id UUID NOT NULL,
    authentication_method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    issued_tenant_version BIGINT NOT NULL,
    issued_user_version BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT user_sessions_pkey
        PRIMARY KEY (session_id),
    CONSTRAINT user_sessions_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_sessions_authentication_method_check
        CHECK (authentication_method IN ('password')),
    CONSTRAINT user_sessions_status_check
        CHECK (status IN ('active', 'revoked')),
    CONSTRAINT user_sessions_version_check
        CHECK (
            issued_tenant_version >= 0
            AND issued_user_version >= 0
            AND version >= 0
        ),
    CONSTRAINT user_sessions_timestamps_check
        CHECK (
            updated_at >= authenticated_at
            AND expires_at > authenticated_at
            AND (
                (status = 'active' AND revoked_at IS NULL)
                OR (
                    status = 'revoked'
                    AND revoked_at IS NOT NULL
                    AND revoked_at >= authenticated_at
                    AND updated_at >= revoked_at
                )
            )
        )
);

CREATE INDEX user_sessions_user_status_expires_idx
    ON user_sessions (tenant_id, user_id, status, expires_at, session_id);

CREATE INDEX user_sessions_expires_idx
    ON user_sessions (expires_at, tenant_id, session_id);
