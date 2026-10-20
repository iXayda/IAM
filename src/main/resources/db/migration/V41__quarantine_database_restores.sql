CREATE TABLE iam_restore (
    id UUID PRIMARY KEY,
    archive_sha256 VARCHAR(64) COLLATE "C" NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    database_name VARCHAR(63) NOT NULL,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(quarantined_at)),
    snapshot_audit_count BIGINT NOT NULL CHECK (snapshot_audit_count >= 0),
    snapshot_last_audit_at TIMESTAMPTZ,
    snapshot_last_audit_id UUID,
    audit_gap_status VARCHAR(16) NOT NULL DEFAULT 'unresolved' CHECK (audit_gap_status='unresolved'),
    CONSTRAINT iam_restore_snapshot CHECK (
        (snapshot_audit_count=0 AND snapshot_last_audit_at IS NULL AND snapshot_last_audit_id IS NULL)
        OR (snapshot_audit_count>0 AND snapshot_last_audit_at IS NOT NULL AND isfinite(snapshot_last_audit_at) AND snapshot_last_audit_id IS NOT NULL)
    )
);
CREATE TABLE iam_restore_state (
    singleton SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton=1),
    current_restore_id UUID REFERENCES iam_restore(id)
);
INSERT INTO iam_restore_state(singleton) VALUES (1);

CREATE FUNCTION iam_protect_restore_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='restore evidence is immutable';
END;
$$;
CREATE TRIGGER iam_restore_evidence_protection BEFORE UPDATE OR DELETE ON iam_restore
    FOR EACH ROW EXECUTE FUNCTION iam_protect_restore_evidence();

CREATE FUNCTION iam_protect_restore_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR (OLD.current_restore_id IS NOT NULL AND NEW.current_restore_id IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='restore isolation state cannot be reset';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_restore_state_protection BEFORE UPDATE OR DELETE ON iam_restore_state
    FOR EACH ROW EXECUTE FUNCTION iam_protect_restore_state();

ALTER TABLE iam_admin_bootstrap ADD COLUMN restore_closed BOOLEAN NOT NULL DEFAULT false;
CREATE FUNCTION iam_protect_bootstrap_closure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.restore_closed AND (TG_OP='DELETE' OR NOT NEW.restore_closed) THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='administrator initialization cannot be reopened';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_admin_bootstrap_closure_protection BEFORE UPDATE OR DELETE ON iam_admin_bootstrap
    FOR EACH ROW EXECUTE FUNCTION iam_protect_bootstrap_closure();

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
        'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'signing_key_compromised', 'signing_key_replaced', 'signing_key_recovered', 'database_restore_quarantined', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'introspection_rejected', 'authorization_access_denied', 'browser_session_access_denied', 'authorization_code_replayed', 'refresh_token_replayed', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'signing_key_compromised', 'signing_key_replaced', 'signing_key_recovered', 'database_restore_quarantined', 'tokens_issued', 'tokens_refreshed', 'authorization_revoked', 'authorization_code_issued', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'signing_key_initialized', 'signing_key_retired', 'signing_key_rotated', 'signing_key_compromised', 'signing_key_replaced', 'signing_key_recovered', 'database_restore_quarantined', 'authorization_request_rejected', 'token_request_rejected', 'user_info_rejected', 'introspection_rejected', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_object_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_object_target CHECK (
    (target_user_id IS NULL AND target_id IS NOT NULL AND target_type IS NOT NULL AND (
        (action IN ('signing_key_retired', 'signing_key_rotated', 'signing_key_compromised', 'signing_key_replaced', 'signing_key_recovered') AND target_type='signing_key')
        OR (action='database_restore_quarantined' AND target_type='database_restore')
        OR (action IN ('resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled') AND target_type = 'resource')
        OR (action IN ('client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated') AND target_type = 'client')
        OR (action IN ('resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled') AND target_type = 'role')
    ))
    OR (action IN ('user_role_granted', 'user_role_revoked') AND target_user_id IS NOT NULL
        AND target_type IS NOT NULL AND target_type = 'role' AND target_id IS NOT NULL)
    OR (action = 'authorization_revoked' AND target_user_id IS NOT NULL AND target_type IS NOT NULL AND target_type='authorization' AND target_id IS NOT NULL)
    OR (action='browser_session_revoked' AND target_user_id IS NOT NULL AND target_type IS NOT NULL AND target_type='browser_session' AND target_id IS NOT NULL)
    OR (action NOT IN ('signing_key_retired', 'signing_key_rotated', 'signing_key_compromised', 'signing_key_replaced', 'signing_key_recovered', 'database_restore_quarantined', 'browser_session_revoked', 'authorization_revoked', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_credential_issued', 'resource_credential_rotated', 'resource_credential_disabled', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled',
        'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked')
        AND target_type IS NULL AND target_id IS NULL)
);
