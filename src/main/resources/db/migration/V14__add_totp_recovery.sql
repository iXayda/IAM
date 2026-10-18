CREATE TABLE iam_totp_recovery (
    user_id UUID PRIMARY KEY,
    recovery_id UUID NOT NULL UNIQUE,
    old_factor_id UUID NOT NULL,
    new_factor_id UUID NOT NULL UNIQUE,
    recovery_generation_id UUID NOT NULL,
    credential_version BIGINT NOT NULL,
    token_digest VARCHAR(64) COLLATE "C" NOT NULL,
    secret_ciphertext VARCHAR(67) COLLATE "C" NOT NULL,
    key_id VARCHAR(64) COLLATE "C" NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_totp_recovery_owner FOREIGN KEY (user_id, old_factor_id)
        REFERENCES iam_user_totp (user_id, factor_id) ON DELETE CASCADE,
    CONSTRAINT iam_totp_recovery_distinct_factor CHECK (old_factor_id <> new_factor_id),
    CONSTRAINT iam_totp_recovery_version CHECK (credential_version > 0),
    CONSTRAINT iam_totp_recovery_digest CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_totp_recovery_secret CHECK (secret_ciphertext ~ '^v1\.[A-Za-z0-9_-]{64}$'),
    CONSTRAINT iam_totp_recovery_key CHECK (key_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_totp_recovery_time CHECK (isfinite(issued_at) AND isfinite(expires_at)
        AND expires_at = issued_at + INTERVAL '10 minutes')
);

CREATE INDEX iam_totp_recovery_cleanup_idx ON iam_totp_recovery (expires_at);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled', 'password_changed',
        'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked', 'password_recovery_issued',
        'password_recovery_cancelled', 'password_recovery_completed', 'password_recovery_failed', 'user_profile_updated',
        'user_disabled', 'user_enabled', 'totp_enrollment_started', 'totp_enrollment_cancelled',
        'totp_enrollment_completed', 'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_authenticated',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_codes_generated',
        'mfa_recovery_code_consumed', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled',
        'totp_recovery_started', 'totp_recovery_completed', 'totp_recovery_failed', 'totp_recovery_throttled'
));
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'browser_session_created', 'browser_session_ended',
        'password_changed', 'browser_sessions_revoked', 'password_recovery_issued', 'password_recovery_cancelled',
        'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled',
        'totp_enrollment_started', 'totp_enrollment_cancelled', 'totp_enrollment_completed', 'totp_authenticated',
        'mfa_recovery_codes_generated', 'mfa_recovery_code_consumed', 'totp_recovery_started', 'totp_recovery_completed'
    ))
    OR (outcome = 'failure' AND action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled'
    )
);
