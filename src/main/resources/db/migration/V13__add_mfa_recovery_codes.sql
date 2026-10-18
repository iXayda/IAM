ALTER TABLE iam_user_totp ADD CONSTRAINT iam_user_totp_owner_factor UNIQUE (user_id, factor_id);

CREATE TABLE iam_mfa_recovery_code (
    user_id UUID NOT NULL,
    factor_id UUID NOT NULL,
    generation_id UUID NOT NULL,
    code_digest VARCHAR(64) COLLATE "C" NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_digest),
    CONSTRAINT iam_mfa_recovery_owner_factor FOREIGN KEY (user_id, factor_id)
        REFERENCES iam_user_totp (user_id, factor_id) ON DELETE CASCADE,
    CONSTRAINT iam_mfa_recovery_digest CHECK (code_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_mfa_recovery_time CHECK (isfinite(issued_at)
        AND (consumed_at IS NULL OR (isfinite(consumed_at) AND consumed_at >= issued_at)))
);

CREATE TABLE iam_mfa_recovery_limit (
    dimension VARCHAR(16) NOT NULL,
    subject_key VARCHAR(64) COLLATE "C" NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    failures INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dimension, subject_key),
    CONSTRAINT iam_mfa_recovery_limit_dimension CHECK (dimension IN ('source', 'account')),
    CONSTRAINT iam_mfa_recovery_limit_key CHECK (subject_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_mfa_recovery_limit_time CHECK (isfinite(window_started_at)),
    CONSTRAINT iam_mfa_recovery_limit_failures CHECK (failures >= 0 AND failures <= CASE dimension WHEN 'account' THEN 5 ELSE 30 END)
);

CREATE INDEX iam_mfa_recovery_limit_cleanup_idx ON iam_mfa_recovery_limit (window_started_at);

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
        'mfa_recovery_code_consumed', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled'
));
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'browser_session_created', 'browser_session_ended',
        'password_changed', 'browser_sessions_revoked', 'password_recovery_issued', 'password_recovery_cancelled',
        'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled',
        'totp_enrollment_started', 'totp_enrollment_cancelled', 'totp_enrollment_completed', 'totp_authenticated',
        'mfa_recovery_codes_generated', 'mfa_recovery_code_consumed'
    ))
    OR (outcome = 'failure' AND action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled'
    )
);
