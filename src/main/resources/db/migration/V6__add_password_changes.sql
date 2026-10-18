ALTER TABLE iam_password ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE iam_password ADD CONSTRAINT iam_password_credential_version CHECK (credential_version > 0);

-- Existing authenticated sessions lack evidence of the version actually verified. Require a fresh login.
DELETE FROM iam_browser_session WHERE principal_name IS NOT NULL;

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled',
        'password_changed', 'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN ('user_created', 'initial_password_set', 'account_setup_issued',
        'account_setup_cancelled', 'account_setup_completed', 'password_authenticated',
        'browser_session_created', 'browser_session_ended', 'password_changed', 'browser_sessions_revoked'))
    OR (outcome = 'failure' AND action IN ('password_auth_failed', 'password_auth_throttled',
        'browser_entry_throttled', 'password_change_failed', 'password_change_throttled'))
);
