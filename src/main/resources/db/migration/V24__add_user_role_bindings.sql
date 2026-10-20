ALTER TABLE iam_resource_role ADD CONSTRAINT iam_resource_role_parent_identity UNIQUE (resource_id, id);

CREATE TABLE iam_user_resource_role_revision (
    user_id UUID NOT NULL REFERENCES iam_user(id),
    resource_id UUID NOT NULL REFERENCES iam_resource(id),
    version BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, resource_id),
    CONSTRAINT iam_user_resource_role_revision_version CHECK (version >= 1),
    CONSTRAINT iam_user_resource_role_revision_time CHECK (isfinite(updated_at))
);

CREATE TABLE iam_user_role (
    user_id UUID NOT NULL,
    resource_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id, resource_id) REFERENCES iam_user_resource_role_revision(user_id, resource_id),
    FOREIGN KEY (resource_id, role_id) REFERENCES iam_resource_role(resource_id, id),
    CONSTRAINT iam_user_role_time CHECK (isfinite(created_at))
);
CREATE INDEX iam_user_role_page_idx ON iam_user_role (user_id, resource_id, created_at, role_id);
CREATE INDEX iam_user_role_by_role_idx ON iam_user_role (role_id, user_id);

CREATE FUNCTION iam_protect_user_role_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'assignment revisions cannot be deleted';
    END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'assignment revisions require stable identities and the next version';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_user_role_revision_protection BEFORE UPDATE OR DELETE ON iam_user_resource_role_revision
    FOR EACH ROW EXECUTE FUNCTION iam_protect_user_role_revision();

CREATE FUNCTION iam_protect_user_role_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'assignments must be revoked and granted to change identity or time';
END;
$$;
CREATE TRIGGER iam_user_role_assignment_protection BEFORE UPDATE ON iam_user_role
    FOR EACH ROW EXECUTE FUNCTION iam_protect_user_role_assignment();

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
        'signing_key_initialized', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'admin_recovery_started', 'admin_recovery_completed', 'signing_key_initialized', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked'
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
        'signing_key_initialized', 'resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled', 'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled'
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_object_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_object_target CHECK (
    (target_user_id IS NULL AND target_id IS NOT NULL AND target_type IS NOT NULL AND (
        (action IN ('resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled') AND target_type = 'resource')
        OR (action IN ('resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled') AND target_type = 'role')
    ))
    OR (action IN ('user_role_granted', 'user_role_revoked') AND target_user_id IS NOT NULL
        AND target_type IS NOT NULL AND target_type = 'role' AND target_id IS NOT NULL)
    OR (action NOT IN ('resource_created', 'resource_updated', 'resource_disabled', 'resource_enabled',
        'resource_role_created', 'resource_role_updated', 'resource_role_disabled', 'resource_role_enabled', 'user_role_granted', 'user_role_revoked')
        AND target_type IS NULL AND target_id IS NULL)
);
