ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled',
        'password_changed', 'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked',
        'password_recovery_issued', 'password_recovery_cancelled', 'password_recovery_completed', 'password_recovery_failed',
        'user_profile_updated', 'user_disabled', 'user_enabled')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN ('user_created', 'initial_password_set', 'account_setup_issued',
        'account_setup_cancelled', 'account_setup_completed', 'password_authenticated',
        'browser_session_created', 'browser_session_ended', 'password_changed', 'browser_sessions_revoked',
        'password_recovery_issued', 'password_recovery_cancelled', 'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled'))
    OR (outcome = 'failure' AND action IN ('password_auth_failed', 'password_auth_throttled',
        'browser_entry_throttled', 'password_change_failed', 'password_change_throttled', 'password_recovery_failed'))
);
