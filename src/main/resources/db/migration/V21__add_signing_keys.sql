CREATE TABLE iam_signing_key (
    id UUID PRIMARY KEY,
    algorithm VARCHAR(5) COLLATE "C" NOT NULL,
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    protection_key_id VARCHAR(64) COLLATE "C" NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT iam_signing_key_algorithm CHECK (algorithm = 'RS256'),
    CONSTRAINT iam_signing_key_public CHECK (octet_length(public_key) BETWEEN 1 AND 1024),
    CONSTRAINT iam_signing_key_private CHECK (octet_length(encrypted_private_key) BETWEEN 1024 AND 4096
        AND get_byte(encrypted_private_key, 0) = 1),
    CONSTRAINT iam_signing_key_protection CHECK (protection_key_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_signing_key_time CHECK (isfinite(created_at))
);

-- Only one signing identity may be stored.
CREATE UNIQUE INDEX iam_signing_key_single_idx ON iam_signing_key ((true));

CREATE TABLE iam_signing_key_state (
    singleton SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    initial_key_id UUID REFERENCES iam_signing_key (id) ON DELETE RESTRICT,
    initialized_at TIMESTAMPTZ,
    CONSTRAINT iam_signing_key_state_time CHECK (
        (initial_key_id IS NULL AND initialized_at IS NULL)
        OR (initial_key_id IS NOT NULL AND initialized_at IS NOT NULL AND isfinite(initialized_at))
    )
);

INSERT INTO iam_signing_key_state (singleton) VALUES (1);

CREATE FUNCTION iam_protect_signing_initialization() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'signing initialization state cannot be deleted';
    END IF;
    IF OLD.initial_key_id IS NOT NULL AND (NEW.initial_key_id IS DISTINCT FROM OLD.initial_key_id
        OR NEW.initialized_at IS DISTINCT FROM OLD.initialized_at) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'signing initialization cannot be reset';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER iam_signing_key_state_protection BEFORE UPDATE OR DELETE ON iam_signing_key_state
    FOR EACH ROW EXECUTE FUNCTION iam_protect_signing_initialization();

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
        'signing_key_initialized'
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
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized'
    ))
    OR (outcome = 'failure' AND action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'password_recovery_throttled', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled',
        'admin_bootstrap_rejected', 'admin_bootstrap_throttled', 'last_administrator_protected', 'admin_mfa_rejected', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed', 'password_recovery_throttled',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled', 'admin_bootstrap_throttled', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled',
        'signing_key_initialized'
    )
);
