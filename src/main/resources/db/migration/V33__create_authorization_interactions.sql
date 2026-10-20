CREATE TABLE iam_authorization_interaction (
    id UUID PRIMARY KEY,
    handle_digest char(64) NOT NULL UNIQUE CHECK (handle_digest ~ '^[0-9a-f]{64}$'),
    owner_digest char(64) NOT NULL CHECK (owner_digest ~ '^[0-9a-f]{64}$'),
    original_authenticated_at BIGINT NOT NULL CHECK (original_authenticated_at >= 0),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    request TEXT NOT NULL CHECK (length(request) <= 131072 AND request LIKE 'enc:v1:%'),
    CHECK (isfinite(created_at) AND isfinite(expires_at) AND expires_at=created_at + INTERVAL '600 seconds'
        AND original_authenticated_at <= floor(extract(epoch FROM created_at) * 1000))
);
CREATE INDEX iam_authorization_interaction_owner_idx ON iam_authorization_interaction(owner_digest,expires_at,id);
CREATE INDEX iam_authorization_interaction_expiry_idx ON iam_authorization_interaction(expires_at,id);

CREATE FUNCTION iam_protect_authorization_interaction() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='authorization interactions are immutable';
END;
$$;
CREATE TRIGGER iam_authorization_interaction_protection BEFORE UPDATE ON iam_authorization_interaction
    FOR EACH ROW EXECUTE FUNCTION iam_protect_authorization_interaction();
