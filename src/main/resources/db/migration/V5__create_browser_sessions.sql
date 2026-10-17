-- Based on Spring Session JDBC 4.1.1 schema-postgresql.sql (Apache-2.0).
CREATE TABLE iam_browser_session (
    primary_id CHAR(36) NOT NULL PRIMARY KEY,
    session_id CHAR(36) NOT NULL,
    creation_time BIGINT NOT NULL,
    last_access_time BIGINT NOT NULL,
    max_inactive_interval INTEGER NOT NULL,
    expiry_time BIGINT NOT NULL,
    principal_name VARCHAR(100)
);
CREATE UNIQUE INDEX iam_browser_session_id ON iam_browser_session (session_id);
CREATE INDEX iam_browser_session_expiry ON iam_browser_session (expiry_time);
CREATE INDEX iam_browser_session_principal ON iam_browser_session (principal_name);

CREATE TABLE iam_browser_session_attributes (
    session_primary_id CHAR(36) NOT NULL,
    attribute_name VARCHAR(200) NOT NULL,
    attribute_bytes BYTEA NOT NULL,
    PRIMARY KEY (session_primary_id, attribute_name),
    FOREIGN KEY (session_primary_id) REFERENCES iam_browser_session (primary_id) ON DELETE CASCADE
);
CREATE INDEX iam_password_authentication_cleanup ON iam_password_authentication_limit (window_started_at);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
        'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled',
        'browser_session_created', 'browser_session_ended', 'browser_entry_throttled')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_target;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN ('password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN ('user_created', 'initial_password_set', 'account_setup_issued',
        'account_setup_cancelled', 'account_setup_completed', 'password_authenticated',
        'browser_session_created', 'browser_session_ended'))
    OR (outcome = 'failure' AND action IN ('password_auth_failed', 'password_auth_throttled', 'browser_entry_throttled'))
);
