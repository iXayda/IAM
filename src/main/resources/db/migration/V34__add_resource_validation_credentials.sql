CREATE TABLE iam_resource_credential (
    resource_id UUID PRIMARY KEY REFERENCES iam_resource(id),
    secret_hash VARCHAR(128) COLLATE "C" NOT NULL,
    status VARCHAR(16) COLLATE "C" NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT iam_resource_credential_hash CHECK (secret_hash ~ '^\{argon2\}\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    CONSTRAINT iam_resource_credential_status CHECK (status IN ('active','disabled')),
    CONSTRAINT iam_resource_credential_version CHECK (version >= 1),
    CONSTRAINT iam_resource_credential_times CHECK (isfinite(created_at) AND isfinite(rotated_at) AND isfinite(updated_at)
        AND created_at <= rotated_at AND rotated_at <= updated_at)
);

CREATE FUNCTION iam_protect_resource_credential() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'resource credential versions cannot be deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.status <> 'active' OR NEW.created_at IS DISTINCT FROM NEW.rotated_at
            OR NEW.created_at IS DISTINCT FROM NEW.updated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'resource credentials require an initial active version';
        END IF;
    ELSE
        IF NEW.resource_id IS DISTINCT FROM OLD.resource_id OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at OR NEW.rotated_at < OLD.rotated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'resource credentials require stable identity and the next version';
        END IF;
        IF NEW.secret_hash = OLD.secret_hash THEN
            IF OLD.status <> 'active' OR NEW.status <> 'disabled' OR NEW.rotated_at IS DISTINCT FROM OLD.rotated_at THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'an existing resource secret can only be disabled';
            END IF;
        ELSIF NEW.status <> 'active' OR NEW.rotated_at IS DISTINCT FROM NEW.updated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'resource credential rotation requires a new active secret';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_resource_credential_protection BEFORE INSERT OR UPDATE OR DELETE ON iam_resource_credential
    FOR EACH ROW EXECUTE FUNCTION iam_protect_resource_credential();

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'account_setup_failed', 'account_setup_throttled', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled', 'password_changed',
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
        'signing_key_initialized', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'authorization_code_replayed', 'refresh_token_replayed', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
));
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN (
        'user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'browser_session_created', 'browser_session_ended',
        'password_changed', 'browser_sessions_revoked', 'password_recovery_issued', 'password_recovery_cancelled',
        'password_recovery_completed', 'user_profile_updated', 'user_disabled', 'user_enabled',
        'totp_enrollment_started', 'totp_enrollment_cancelled', 'totp_enrollment_completed', 'totp_authenticated',
        'mfa_recovery_codes_generated', 'mfa_recovery_code_consumed', 'totp_recovery_started', 'totp_recovery_completed',
        'totp_replacement_started', 'totp_replacement_completed', 'admin_bootstrap_prepared', 'admin_bootstrap_completed', 'admin_mfa_authenticated',
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
    ))
    OR (outcome = 'failure' AND action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'password_recovery_throttled', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled',
        'admin_bootstrap_rejected', 'admin_bootstrap_throttled', 'last_administrator_protected', 'admin_mfa_rejected', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'authorization_code_replayed', 'refresh_token_replayed'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed', 'password_recovery_throttled',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled', 'admin_bootstrap_throttled', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled',
        'signing_key_initialized', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_object_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_object_target CHECK (
    (target_user_id IS NULL AND target_id IS NOT NULL AND target_type IS NOT NULL AND (
        (action IN ('resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled') AND target_type = 'resource')
        OR (action IN ('client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated') AND target_type = 'client')
        OR (action IN ('resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled') AND target_type = 'role')
    ))
    OR (action IN ('user_role_granted', 'user_role_revoked') AND target_user_id IS NOT NULL
        AND target_type IS NOT NULL AND target_type = 'role' AND target_id IS NOT NULL)
    OR (action = 'authorization_revoked' AND target_user_id IS NOT NULL AND target_type IS NOT NULL AND target_type='authorization' AND target_id IS NOT NULL)
    OR (action NOT IN ('authorization_revoked', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled',
        'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked')
        AND target_type IS NULL AND target_id IS NULL)
);
