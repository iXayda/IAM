ALTER TABLE iam_authorization_record ADD CONSTRAINT iam_authorization_record_subjects UNIQUE (id,user_id,client_id);

CREATE TABLE iam_authorization_binding (
    authorization_id varchar(100) PRIMARY KEY,
    user_id UUID NOT NULL,
    client_id varchar(100) NOT NULL,
    resource_id UUID NOT NULL REFERENCES iam_resource(id),
    audience varchar(256) NOT NULL CHECK (char_length(audience) BETWEEN 1 AND 256 AND audience ~ '^[!-~]+$'),
    credential_version BIGINT NOT NULL CHECK (credential_version >= 1),
    client_version BIGINT NOT NULL CHECK (client_version >= 1),
    resource_version BIGINT NOT NULL CHECK (resource_version >= 1),
    assignment_version BIGINT NOT NULL CHECK (assignment_version >= 0),
    browser_session_id char(36) NOT NULL CHECK (browser_session_id::uuid::text = browser_session_id),
    authenticated_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    scopes varchar(64) NOT NULL CHECK (scopes IN ('openid','openid,profile','offline_access,openid','offline_access,openid,profile')),
    issued_at timestamptz NOT NULL,
    code_expires_at timestamptz NOT NULL,
    FOREIGN KEY (authorization_id,user_id,client_id) REFERENCES iam_authorization_record(id,user_id,client_id),
    UNIQUE (authorization_id,resource_id),
    CONSTRAINT iam_authorization_binding_times CHECK (
        isfinite(authenticated_at) AND isfinite(idle_expires_at) AND isfinite(absolute_expires_at)
        AND isfinite(issued_at) AND isfinite(code_expires_at)
        AND authenticated_at <= issued_at AND issued_at < code_expires_at
        AND code_expires_at <= issued_at + INTERVAL '60 seconds'
        AND code_expires_at <= idle_expires_at AND code_expires_at <= absolute_expires_at
        AND absolute_expires_at <= authenticated_at + INTERVAL '8 hours'
    )
);
CREATE INDEX iam_authorization_binding_user_idx ON iam_authorization_binding(user_id,authorization_id);
CREATE INDEX iam_authorization_binding_client_idx ON iam_authorization_binding(client_id,authorization_id);
CREATE INDEX iam_authorization_binding_resource_idx ON iam_authorization_binding(resource_id,authorization_id);
CREATE INDEX iam_authorization_binding_session_idx ON iam_authorization_binding(browser_session_id,authorization_id);

-- No session FK: deleting a browser session must not erase the independent grant or its replay-detection bounds.
CREATE TABLE iam_authorization_binding_role (
    authorization_id varchar(100) NOT NULL,
    resource_id UUID NOT NULL,
    role_id UUID NOT NULL,
    code varchar(64) NOT NULL CHECK (code ~ '^[a-z][a-z0-9_]{0,63}$'),
    version BIGINT NOT NULL CHECK (version >= 1),
    PRIMARY KEY (authorization_id,role_id),
    UNIQUE (authorization_id,code),
    FOREIGN KEY (authorization_id,resource_id) REFERENCES iam_authorization_binding(authorization_id,resource_id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id,role_id) REFERENCES iam_resource_role(resource_id,id)
);

CREATE FUNCTION iam_protect_authorization_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='original authorization bounds are immutable';
END;
$$;
CREATE TRIGGER iam_authorization_binding_protection BEFORE UPDATE ON iam_authorization_binding
    FOR EACH ROW EXECUTE FUNCTION iam_protect_authorization_binding();
CREATE TRIGGER iam_authorization_binding_role_protection BEFORE UPDATE ON iam_authorization_binding_role
    FOR EACH ROW EXECUTE FUNCTION iam_protect_authorization_binding();

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
        'signing_key_initialized', 'authorization_code_issued', 'authorization_request_rejected', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'authorization_code_issued', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
    ))
    OR (outcome = 'failure' AND action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_change_failed',
        'password_change_throttled', 'password_recovery_failed', 'password_recovery_throttled', 'totp_enrollment_failed', 'totp_enrollment_throttled',
        'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled',
        'admin_bootstrap_rejected', 'admin_bootstrap_throttled', 'last_administrator_protected', 'admin_mfa_rejected', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled', 'authorization_request_rejected'
    ))
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN (
        'account_setup_failed', 'account_setup_throttled', 'password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled', 'password_recovery_failed', 'password_recovery_throttled',
        'totp_enrollment_failed', 'totp_enrollment_throttled', 'totp_auth_failed', 'totp_auth_throttled', 'mfa_recovery_code_failed', 'mfa_recovery_code_throttled', 'totp_recovery_failed', 'totp_recovery_throttled',
        'totp_replacement_failed', 'totp_replacement_throttled', 'admin_bootstrap_throttled', 'admin_access_denied', 'admin_recovery_rejected', 'admin_recovery_throttled',
        'signing_key_initialized', 'authorization_request_rejected', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);
