CREATE TABLE iam_security_audit (
    id UUID PRIMARY KEY,
    actor VARCHAR(128) NOT NULL,
    source VARCHAR(64) NOT NULL,
    correlation_id UUID NOT NULL,
    target_user_id UUID NOT NULL,
    action VARCHAR(32) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT iam_security_audit_actor CHECK (actor ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$'),
    CONSTRAINT iam_security_audit_source CHECK (source ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,63}$'),
    CONSTRAINT iam_security_audit_action CHECK (action IN ('user_created', 'initial_password_set')),
    CONSTRAINT iam_security_audit_outcome CHECK (outcome = 'success')
);
