CREATE TABLE iam_user_totp (
    user_id UUID PRIMARY KEY REFERENCES iam_user (id) ON DELETE RESTRICT,
    factor_id UUID NOT NULL UNIQUE,
    secret_ciphertext VARCHAR(67) COLLATE "C" NOT NULL,
    key_id VARCHAR(64) COLLATE "C" NOT NULL,
    enrollment_credential_version BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    last_used_step BIGINT,
    CONSTRAINT iam_user_totp_secret CHECK (secret_ciphertext ~ '^v1\.[A-Za-z0-9_-]{64}$'),
    CONSTRAINT iam_user_totp_key CHECK (key_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_user_totp_version CHECK (enrollment_credential_version > 0),
    CONSTRAINT iam_user_totp_time CHECK (isfinite(issued_at) AND isfinite(expires_at) AND expires_at > issued_at),
    CONSTRAINT iam_user_totp_state CHECK (
        (status = 'pending' AND activated_at IS NULL AND last_used_step IS NULL)
        OR (status = 'active' AND activated_at IS NOT NULL AND isfinite(activated_at)
            AND activated_at >= issued_at AND activated_at < expires_at AND last_used_step IS NOT NULL AND last_used_step >= 0)
    )
);

CREATE TABLE iam_totp_authentication_limit (
    dimension VARCHAR(16) NOT NULL,
    subject_key VARCHAR(64) COLLATE "C" NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    failures INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dimension, subject_key),
    CONSTRAINT iam_totp_limit_dimension CHECK (dimension IN ('source', 'account')),
    CONSTRAINT iam_totp_limit_key CHECK (subject_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_totp_limit_time CHECK (isfinite(window_started_at)),
    CONSTRAINT iam_totp_limit_failures CHECK (failures >= 0 AND failures <= CASE dimension WHEN 'account' THEN 5 ELSE 30 END)
);

CREATE INDEX iam_totp_limit_cleanup_idx ON iam_totp_authentication_limit (window_started_at);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled', 'password_changed',
        'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked', 'password_recovery_issued',
        'password_recovery_cancelled', 'password_recovery_completed', 'password_recovery_failed', 'user_profile_updated',
        'user_disabled', 'user_enabled', 'totp_enrollment_started', 'totp_enrollment_cancelled',
        'totp_enrollment_completed', 'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_authenticated',
        'totp_auth_failed', 'totp_auth_throttled'
));
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'browser_session_created', 'browser_session_ended',
        'password_changed', 'browser_sessions_revoked', 'password_recovery_issued', 'password_recovery_cancelled',
        'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled',
        'totp_enrollment_started', 'totp_enrollment_cancelled', 'totp_enrollment_completed', 'totp_authenticated'
    ))
    OR (outcome = 'failure' AND action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled'
    )
);
