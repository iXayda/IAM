ALTER TABLE user_sessions
    ADD CONSTRAINT user_sessions_tenant_session_key
        UNIQUE (tenant_id, session_id);

CREATE TABLE user_session_authentication_factors (
    tenant_id UUID NOT NULL,
    session_id UUID NOT NULL,
    factor TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT user_session_authentication_factors_pkey
        PRIMARY KEY (tenant_id, session_id, factor),
    CONSTRAINT user_session_authentication_factors_session_fk
        FOREIGN KEY (tenant_id, session_id)
        REFERENCES user_sessions (tenant_id, session_id) ON DELETE CASCADE,
    CONSTRAINT user_session_authentication_factors_factor_check
        CHECK (factor IN ('password', 'totp', 'recovery_code')),
    CONSTRAINT user_session_authentication_factors_issued_at_check
        CHECK (issued_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00')
);

INSERT INTO user_session_authentication_factors (tenant_id, session_id, factor, issued_at)
SELECT tenant_id, session_id, 'password', authenticated_at
FROM user_sessions
WHERE authentication_method = 'password';
