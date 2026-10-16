CREATE TABLE iam_password_authentication_limit (
    dimension VARCHAR(16) NOT NULL,
    subject_key VARCHAR(64) COLLATE "C" NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    failures INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (dimension, subject_key),
    CONSTRAINT iam_password_authentication_dimension CHECK (dimension IN ('source', 'account')),
    CONSTRAINT iam_password_authentication_key CHECK (subject_key ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_password_authentication_time CHECK (isfinite(window_started_at)),
    CONSTRAINT iam_password_authentication_failures CHECK (
        failures >= 0 AND failures <= CASE dimension WHEN 'account' THEN 10 ELSE 50 END
    )
);

ALTER TABLE iam_security_audit ALTER COLUMN target_user_id DROP NOT NULL;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_target CHECK (
    target_user_id IS NOT NULL OR action IN ('password_auth_failed', 'password_auth_throttled')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued', 'account_setup_cancelled',
               'account_setup_completed', 'password_authenticated', 'password_auth_failed', 'password_auth_throttled')
);
ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_outcome;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_outcome CHECK (
    (outcome = 'success' AND action IN ('user_created', 'initial_password_set', 'account_setup_issued',
        'account_setup_cancelled', 'account_setup_completed', 'password_authenticated'))
    OR (outcome = 'failure' AND action IN ('password_auth_failed', 'password_auth_throttled'))
);
