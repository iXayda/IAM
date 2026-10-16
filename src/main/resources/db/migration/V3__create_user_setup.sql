CREATE TABLE iam_user_setup (
    user_id UUID PRIMARY KEY REFERENCES iam_user (id) ON DELETE RESTRICT,
    token_digest VARCHAR(64) COLLATE "C" NOT NULL UNIQUE,
    status VARCHAR(16) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    CONSTRAINT iam_user_setup_digest CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT iam_user_setup_status CHECK (status IN ('issued', 'consumed', 'cancelled')),
    CONSTRAINT iam_user_setup_expiry CHECK (isfinite(issued_at) AND isfinite(expires_at) AND expires_at > issued_at),
    CONSTRAINT iam_user_setup_finish CHECK (
        (status = 'issued' AND finished_at IS NULL)
        OR (status IN ('consumed', 'cancelled') AND finished_at IS NOT NULL AND isfinite(finished_at) AND finished_at >= issued_at)
    )
);

ALTER TABLE iam_security_audit DROP CONSTRAINT iam_security_audit_action;
ALTER TABLE iam_security_audit ADD CONSTRAINT iam_security_audit_action CHECK (
    action IN ('user_created', 'initial_password_set', 'account_setup_issued',
               'account_setup_cancelled', 'account_setup_completed')
);
