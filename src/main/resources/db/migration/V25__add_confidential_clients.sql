-- Spring Security 7.1.1 registered-client schema, using timestamptz as required for PostgreSQL.
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamptz DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL CHECK (post_logout_redirect_uris IS NULL OR post_logout_redirect_uris = ''),
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT iam_client_identity CHECK (id = client_id AND id::uuid::text = id),
    CONSTRAINT iam_client_secret_hash CHECK (client_secret IS NOT NULL AND client_secret LIKE '{argon2}$argon2id$%'),
    CONSTRAINT iam_client_auth_method CHECK (client_authentication_methods = 'client_secret_basic'),
    CONSTRAINT iam_client_issued_time CHECK (isfinite(client_id_issued_at)),
    CONSTRAINT iam_client_secret_expiry CHECK (client_secret_expires_at IS NULL)
);
CREATE UNIQUE INDEX oauth2_registered_client_id_idx ON oauth2_registered_client(client_id);

CREATE TABLE iam_client (
    id varchar(100) PRIMARY KEY REFERENCES oauth2_registered_client(id),
    resource_id UUID NOT NULL REFERENCES iam_resource(id),
    status varchar(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    secret_rotated_at timestamptz NOT NULL,
    UNIQUE (id, resource_id),
    CONSTRAINT iam_client_times CHECK (isfinite(created_at) AND isfinite(updated_at) AND isfinite(secret_rotated_at)
        AND updated_at >= created_at AND secret_rotated_at >= created_at AND secret_rotated_at <= updated_at)
);
CREATE INDEX iam_client_page_idx ON iam_client(created_at,id);
CREATE INDEX iam_client_status_page_idx ON iam_client(status,created_at,id);
CREATE INDEX iam_client_resource_idx ON iam_client(resource_id,id);
CREATE TABLE iam_client_allowed_role (
    client_id varchar(100) NOT NULL,
    resource_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (client_id,role_id),
    FOREIGN KEY (client_id,resource_id) REFERENCES iam_client(id,resource_id),
    FOREIGN KEY (resource_id,role_id) REFERENCES iam_resource_role(resource_id,id)
);
CREATE INDEX iam_client_allowed_role_reverse_idx ON iam_client_allowed_role(role_id,client_id);

CREATE FUNCTION iam_protect_registered_client() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'client identities cannot be deleted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.client_id IS DISTINCT FROM OLD.client_id
        OR NEW.client_id_issued_at IS DISTINCT FROM OLD.client_id_issued_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'client identities and creation times are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_registered_client_protection BEFORE UPDATE OR DELETE ON oauth2_registered_client
    FOR EACH ROW EXECUTE FUNCTION iam_protect_registered_client();

CREATE FUNCTION iam_protect_client_state() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'client state cannot be deleted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at OR NEW.secret_rotated_at < OLD.secret_rotated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'client changes require stable identity and the next version';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_client_state_protection BEFORE UPDATE OR DELETE ON iam_client
    FOR EACH ROW EXECUTE FUNCTION iam_protect_client_state();

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
        'signing_key_initialized', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'signing_key_initialized', 'client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_object_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_object_target CHECK (
    (target_user_id IS NULL AND target_id IS NOT NULL AND target_type IS NOT NULL AND (
        (action IN ('resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled') AND target_type = 'resource')
        OR (action IN ('client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated') AND target_type = 'client')
        OR (action IN ('resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled') AND target_type = 'role')
    ))
    OR (action IN ('user_role_granted', 'user_role_revoked') AND target_user_id IS NOT NULL
        AND target_type IS NOT NULL AND target_type = 'role' AND target_id IS NOT NULL)
    OR (action NOT IN ('client_created', 'client_updated', 'client_disabled', 'client_enabled', 'client_secret_rotated', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled',
        'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked')
        AND target_type IS NULL AND target_id IS NULL)
);
