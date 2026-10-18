CREATE TABLE iam_password_recovery (
    user_id UUID PRIMARY KEY REFERENCES iam_user (id) ON DELETE RESTRICT,
    token_digest VARCHAR(64) COLLATE "C" NOT NULL UNIQUE,
    credential_version BIGINT NOT NULL CHECK (credential_version > 0),
    status VARCHAR(16) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    CONSTRAINT iam_password_recovery_digest CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_password_recovery_status CHECK (status IN ('issued', 'consumed', 'cancelled')),
    CONSTRAINT iam_password_recovery_expiry CHECK (isfinite(issued_at) AND isfinite(expires_at) AND expires_at > issued_at),
    CONSTRAINT iam_password_recovery_finish CHECK (
        (status = 'issued' AND finished_at IS NULL)
        OR (status IN ('consumed', 'cancelled') AND finished_at IS NOT NULL AND isfinite(finished_at) AND finished_at >= issued_at)
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled',
        'password_changed', 'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked',
        'password_recovery_issued', 'password_recovery_cancelled', 'password_recovery_completed', 'password_recovery_failed')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN ('user_created', 'initial_password_set', 'account_setup_issued',
        'account_setup_cancelled', 'account_setup_completed', 'password_authenticated',
        'browser_session_created', 'browser_session_ended', 'password_changed', 'browser_sessions_revoked',
        'password_recovery_issued', 'password_recovery_cancelled', 'password_recovery_completed'))
    OR (outcome = 'failure' AND action IN ('password_auth_failed', 'password_auth_throttled',
        'browser_entry_throttled', 'password_change_failed', 'password_change_throttled', 'password_recovery_failed'))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN ('password_auth_failed', 'password_auth_throttled',
        'browser_entry_throttled', 'password_recovery_failed')
);
