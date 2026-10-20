ALTER TABLE iam_signing_key ADD COLUMN status VARCHAR(8) NOT NULL DEFAULT 'active';
ALTER TABLE iam_signing_key ADD COLUMN retired_at TIMESTAMPTZ;
ALTER TABLE iam_signing_key ADD COLUMN verification_until TIMESTAMPTZ;
ALTER TABLE iam_signing_key ALTER COLUMN encrypted_private_key DROP NOT NULL;
ALTER TABLE iam_signing_key ALTER COLUMN protection_key_id DROP NOT NULL;
ALTER TABLE iam_signing_key ADD CONSTRAINT iam_signing_key_lifecycle CHECK (
    (status='active' AND encrypted_private_key IS NOT NULL AND protection_key_id IS NOT NULL AND retired_at IS NULL AND verification_until IS NULL)
    OR (status='retired' AND encrypted_private_key IS NULL AND protection_key_id IS NULL
        AND retired_at IS NOT NULL AND verification_until IS NOT NULL AND isfinite(retired_at) AND isfinite(verification_until)
        AND retired_at >= created_at AND verification_until = retired_at + interval '330 seconds')
);
DROP INDEX iam_signing_key_single_idx;
CREATE UNIQUE INDEX iam_signing_key_active_idx ON iam_signing_key ((true)) WHERE status='active';

ALTER TABLE iam_signing_key_state ADD COLUMN active_key_id UUID REFERENCES iam_signing_key(id) ON DELETE RESTRICT;
ALTER TABLE iam_signing_key_state ADD COLUMN active_key_created_at TIMESTAMPTZ;
ALTER TABLE iam_signing_key_state ADD COLUMN revision BIGINT NOT NULL DEFAULT 0;
UPDATE iam_signing_key_state SET active_key_id=initial_key_id,active_key_created_at=initialized_at,revision=CASE WHEN initial_key_id IS NULL THEN 0 ELSE 1 END;
ALTER TABLE iam_signing_key_state ADD CONSTRAINT iam_signing_key_state_active CHECK (
    (initial_key_id IS NULL AND active_key_id IS NULL AND active_key_created_at IS NULL AND revision=0)
    OR (initial_key_id IS NOT NULL AND active_key_id IS NOT NULL AND active_key_created_at IS NOT NULL AND isfinite(active_key_created_at) AND revision>0)
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'account_setup_failed', 'account_setup_throttled', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_session_revoked', 'browser_entry_throttled', 'all_sessions_revoked', 'password_changed',
        'password_change_failed', 'password_change_throttled', 'browser_sessions_revoked', 'password_recovery_issued',
        'password_recovery_cancelled', 'password_recovery_completed', 'password_recovery_failed', 'password_recovery_throttled', 'user_profile_updated',
        'user_disabled', 'user_enabled', 'totp_enrollment_started', 'totp_enrollment_cancelled',
        'totp_enrollment_completed', 'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_authenticated',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_codes_generated',
        'mfa_recovery_code_consumed', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled',
        'totp_recovery_started', 'totp_recovery_completed',
        'totp_replacement_started', 'totp_replacement_completed', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled',
        'admin_bootstrap_prepared', 'admin_bootstrap_completed', 'admin_bootstrap_rejected', 'admin_bootstrap_throttled', 'last_administrator_protected',
        'admin_mfa_authenticated', 'admin_mfa_rejected', 'admin_access_denied',
        'admin_recovery_started', 'admin_recovery_completed', 'admin_recovery_rejected', 'admin_recovery_throttled',
        'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'introspection_rejected', 'authorization_access_denied', 'browser_session_access_denied', 'authorization_code_replayed', 'refresh_token_replayed', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
));
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'browser_session_created', 'browser_session_ended', 'browser_session_revoked',
        'all_sessions_revoked', 'password_changed', 'browser_sessions_revoked', 'password_recovery_issued', 'password_recovery_cancelled',
        'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled',
        'totp_enrollment_started', 'totp_enrollment_cancelled', 'totp_enrollment_completed', 'totp_authenticated',
        'mfa_recovery_codes_generated', 'mfa_recovery_code_consumed', 'totp_recovery_started', 'totp_recovery_completed',
        'totp_replacement_started', 'totp_replacement_completed', 'admin_bootstrap_prepared', 'admin_bootstrap_completed', 'admin_mfa_authenticated',
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
    ))
    OR (outcome = 'failure' AND action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'password_recovery_throttled', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled',
        'admin_bootstrap_rejected', 'admin_bootstrap_throttled', 'last_administrator_protected', 'admin_mfa_rejected', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'introspection_rejected', 'authorization_access_denied', 'browser_session_access_denied', 'authorization_code_replayed', 'refresh_token_replayed'
    ))
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed', 'password_recovery_throttled',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled', 'admin_bootstrap_throttled', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled',
        'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'introspection_rejected', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_object_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_object_target CHECK (
    (target_user_id IS NULL AND target_id IS NOT NULL AND target_type IS NOT NULL AND (
        (action IN ('signing_key_retired', 'signing_key_rotated') AND target_type='signing_key')
        OR (action IN ('resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled') AND target_type = 'resource')
        OR (action IN ('client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated') AND target_type = 'client')
        OR (action IN ('resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled') AND target_type = 'role')
    ))
    OR (action IN ('user_role_granted', 'user_role_revoked') AND target_user_id IS NOT NULL
        AND target_type IS NOT NULL AND target_type = 'role' AND target_id IS NOT NULL)
    OR (action = 'authorization_revoked' AND target_user_id IS NOT NULL AND target_type IS NOT NULL AND target_type='authorization' AND target_id IS NOT NULL)
    OR (action='browser_session_revoked' AND target_user_id IS NOT NULL AND target_type IS NOT NULL AND target_type='browser_session' AND target_id IS NOT NULL)
    OR (action NOT IN ('signing_key_retired', 'signing_key_rotated', 'browser_session_revoked', 'authorization_revoked', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled',
        'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked')
        AND target_type IS NULL AND target_id IS NULL)
);
