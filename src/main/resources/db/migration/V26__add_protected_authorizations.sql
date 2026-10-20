-- Spring Security 7.1.1 schema with PostgreSQL text/timestamptz and encrypted state.
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text NOT NULL,
    state text DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamptz DEFAULT NULL,
    authorization_code_expires_at timestamptz DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamptz DEFAULT NULL,
    access_token_expires_at timestamptz DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamptz DEFAULT NULL,
    oidc_id_token_expires_at timestamptz DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamptz DEFAULT NULL,
    refresh_token_expires_at timestamptz DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    user_code_value text DEFAULT NULL,
    user_code_issued_at timestamptz DEFAULT NULL,
    user_code_expires_at timestamptz DEFAULT NULL,
    user_code_metadata text DEFAULT NULL,
    device_code_value text DEFAULT NULL,
    device_code_issued_at timestamptz DEFAULT NULL,
    device_code_expires_at timestamptz DEFAULT NULL,
    device_code_metadata text DEFAULT NULL,
    PRIMARY KEY (id)
);

ALTER TABLE oauth2_authorization ADD CONSTRAINT iam_authorization_identity CHECK (id::uuid::text = id AND principal_name::uuid::text = principal_name);
ALTER TABLE oauth2_authorization ADD CONSTRAINT iam_authorization_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client(id);
ALTER TABLE oauth2_authorization ADD CONSTRAINT iam_authorization_grant CHECK (authorization_grant_type = 'authorization_code');
ALTER TABLE oauth2_authorization ADD CONSTRAINT iam_authorization_unsupported_tokens CHECK (user_code_value IS NULL AND user_code_issued_at IS NULL AND user_code_expires_at IS NULL AND user_code_metadata IS NULL AND device_code_value IS NULL AND device_code_issued_at IS NULL AND device_code_expires_at IS NULL AND device_code_metadata IS NULL);
ALTER TABLE oauth2_authorization ADD CHECK (attributes LIKE 'enc:v1:%' AND octet_length(attributes) <= 131072);
ALTER TABLE oauth2_authorization ADD CHECK (state IS NULL OR (state LIKE 'enc:v1:%' AND octet_length(state) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (authorization_code_value IS NULL OR (authorization_code_value LIKE 'enc:v1:%' AND octet_length(authorization_code_value) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (authorization_code_metadata IS NULL OR (authorization_code_metadata LIKE 'enc:v1:%' AND octet_length(authorization_code_metadata) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (access_token_value IS NULL OR (access_token_value LIKE 'enc:v1:%' AND octet_length(access_token_value) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (access_token_metadata IS NULL OR (access_token_metadata LIKE 'enc:v1:%' AND octet_length(access_token_metadata) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (oidc_id_token_value IS NULL OR (oidc_id_token_value LIKE 'enc:v1:%' AND octet_length(oidc_id_token_value) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (oidc_id_token_metadata IS NULL OR (oidc_id_token_metadata LIKE 'enc:v1:%' AND octet_length(oidc_id_token_metadata) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (refresh_token_value IS NULL OR (refresh_token_value LIKE 'enc:v1:%' AND octet_length(refresh_token_value) <= 131072));
ALTER TABLE oauth2_authorization ADD CHECK (refresh_token_metadata IS NULL OR (refresh_token_metadata LIKE 'enc:v1:%' AND octet_length(refresh_token_metadata) <= 131072));

CREATE TABLE iam_authorization_record (
    id varchar(100) PRIMARY KEY REFERENCES oauth2_authorization(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES iam_user(id),
    client_id varchar(100) NOT NULL REFERENCES oauth2_registered_client(id),
    version BIGINT NOT NULL CHECK (version >= 1)
);
CREATE INDEX iam_authorization_record_user_idx ON iam_authorization_record(user_id,id);
CREATE INDEX iam_authorization_record_client_idx ON iam_authorization_record(client_id,id);
CREATE TABLE iam_authorization_token_index (
    authorization_id varchar(100) NOT NULL REFERENCES iam_authorization_record(id) ON DELETE CASCADE,
    token_type varchar(24) NOT NULL CHECK (token_type IN ('state','code','access_token','id_token','refresh_token')),
    digest char(64) NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (authorization_id,token_type)
);
CREATE INDEX iam_authorization_token_lookup_idx ON iam_authorization_token_index(digest,token_type,authorization_id);
CREATE UNIQUE INDEX iam_authorization_token_identity_idx ON iam_authorization_token_index(token_type,digest) WHERE token_type <> 'state';

CREATE FUNCTION iam_protect_authorization_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.registered_client_id IS DISTINCT FROM OLD.registered_client_id
        OR NEW.principal_name IS DISTINCT FROM OLD.principal_name OR NEW.authorization_grant_type IS DISTINCT FROM OLD.authorization_grant_type THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='authorization identities and subjects are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_authorization_identity_protection BEFORE UPDATE ON oauth2_authorization
    FOR EACH ROW EXECUTE FUNCTION iam_protect_authorization_identity();

CREATE FUNCTION iam_protect_authorization_record() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.client_id IS DISTINCT FROM OLD.client_id
        OR NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='authorization records require stable subjects and the next version';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER iam_authorization_record_protection BEFORE UPDATE ON iam_authorization_record
    FOR EACH ROW EXECUTE FUNCTION iam_protect_authorization_record();
