CREATE TABLE user_totp_credentials (
    credential_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    status TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'sha1',
    digits SMALLINT NOT NULL DEFAULT 6,
    period_seconds SMALLINT NOT NULL DEFAULT 30,
    secret_encryption_key_id TEXT,
    secret_protection_version SMALLINT NOT NULL DEFAULT 1,
    secret_initialization_vector BYTEA,
    secret_ciphertext BYTEA,
    last_accepted_time_step BIGINT,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    enrollment_expires_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT user_totp_credentials_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_totp_credentials_status_check
        CHECK (status IN ('pending', 'active', 'revoked')),
    CONSTRAINT user_totp_credentials_parameters_check
        CHECK (
            algorithm = 'sha1'
            AND digits = 6
            AND period_seconds = 30
            AND secret_protection_version = 1
        ),
    CONSTRAINT user_totp_credentials_key_id_check
        CHECK (
            secret_encryption_key_id IS NULL
            OR (
                char_length(secret_encryption_key_id) BETWEEN 1 AND 64
                AND secret_encryption_key_id ~ '^[A-Za-z0-9._-]+$'
            )
        ),
    CONSTRAINT user_totp_credentials_secret_check
        CHECK (
            (
                secret_encryption_key_id IS NULL
                AND secret_initialization_vector IS NULL
                AND secret_ciphertext IS NULL
            )
            OR (
                secret_encryption_key_id IS NOT NULL
                AND secret_initialization_vector IS NOT NULL
                AND secret_ciphertext IS NOT NULL
                AND octet_length(secret_initialization_vector) = 12
                AND octet_length(secret_ciphertext) = 36
            )
        ),
    CONSTRAINT user_totp_credentials_version_check
        CHECK (version >= 0),
    CONSTRAINT user_totp_credentials_time_step_check
        CHECK (last_accepted_time_step IS NULL OR last_accepted_time_step >= 0),
    CONSTRAINT user_totp_credentials_timestamps_check
        CHECK (
            updated_at >= created_at
            AND (activated_at IS NULL OR activated_at BETWEEN created_at AND updated_at)
            AND (revoked_at IS NULL OR revoked_at BETWEEN created_at AND updated_at)
        ),
    CONSTRAINT user_totp_credentials_lifecycle_check
        CHECK (
            (
                status = 'pending'
                AND secret_encryption_key_id IS NOT NULL
                AND enrollment_expires_at IS NOT NULL
                AND enrollment_expires_at > created_at
                AND activated_at IS NULL
                AND revoked_at IS NULL
                AND last_accepted_time_step IS NULL
            )
            OR (
                status = 'active'
                AND secret_encryption_key_id IS NOT NULL
                AND version > 0
                AND enrollment_expires_at IS NULL
                AND activated_at IS NOT NULL
                AND revoked_at IS NULL
                AND last_accepted_time_step IS NOT NULL
            )
            OR (
                status = 'revoked'
                AND secret_encryption_key_id IS NULL
                AND version > 0
                AND enrollment_expires_at IS NULL
                AND revoked_at IS NOT NULL
                AND revoked_at = updated_at
                AND (
                    (activated_at IS NULL AND last_accepted_time_step IS NULL)
                    OR (activated_at IS NOT NULL AND last_accepted_time_step IS NOT NULL)
                )
            )
        )
);

CREATE UNIQUE INDEX user_totp_credentials_active_user_key
    ON user_totp_credentials (tenant_id, user_id)
    WHERE status = 'active';

CREATE UNIQUE INDEX user_totp_credentials_pending_user_key
    ON user_totp_credentials (tenant_id, user_id)
    WHERE status = 'pending';

CREATE UNIQUE INDEX user_totp_credentials_secret_iv_key
    ON user_totp_credentials (secret_encryption_key_id, secret_initialization_vector)
    WHERE secret_encryption_key_id IS NOT NULL;

CREATE INDEX user_totp_credentials_pending_expiry_idx
    ON user_totp_credentials (enrollment_expires_at, tenant_id, user_id)
    WHERE status = 'pending';
