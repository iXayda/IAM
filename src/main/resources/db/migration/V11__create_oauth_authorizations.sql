ALTER TABLE user_sessions
    ADD CONSTRAINT user_sessions_tenant_user_session_key
        UNIQUE (tenant_id, user_id, session_id);

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_tenant_client_identifier_key
        UNIQUE (tenant_id, client_id, client_identifier);

CREATE TABLE oauth_authorizations (
    authorization_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    client_identifier TEXT COLLATE "C" NOT NULL,
    principal_name TEXT COLLATE "C" NOT NULL,
    authorization_grant_type TEXT NOT NULL DEFAULT 'authorization_code',
    authorization_uri TEXT COLLATE "C" NOT NULL,
    redirect_uri TEXT COLLATE "C",
    client_state TEXT COLLATE "C",
    request_version SMALLINT NOT NULL DEFAULT 1,
    request_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    purge_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT oauth_authorizations_tenant_client_authorization_key
        UNIQUE (tenant_id, client_id, authorization_id),
    CONSTRAINT oauth_authorizations_client_fk
        FOREIGN KEY (tenant_id, client_id, client_identifier)
        REFERENCES oauth_clients (tenant_id, client_id, client_identifier) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorizations_session_fk
        FOREIGN KEY (tenant_id, user_id, session_id)
        REFERENCES user_sessions (tenant_id, user_id, session_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorizations_redirect_uri_fk
        FOREIGN KEY (tenant_id, client_id, redirect_uri)
        REFERENCES oauth_client_redirect_uris (tenant_id, client_id, redirect_uri) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorizations_identity_check
        CHECK (
            principal_name = user_id::text
            AND char_length(client_identifier) BETWEEN 1 AND 128
            AND octet_length(client_identifier) = char_length(client_identifier)
            AND client_identifier ~ '^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$'
        ),
    CONSTRAINT oauth_authorizations_grant_check
        CHECK (authorization_grant_type = 'authorization_code'),
    CONSTRAINT oauth_authorizations_request_check
        CHECK (
            request_version = 1
            AND jsonb_typeof(request_parameters) = 'object'
            AND request_parameters - ARRAY[
                'code_challenge', 'code_challenge_method', 'nonce', 'prompt'
            ]::text[] = '{}'::jsonb
            AND request_parameters ? 'code_challenge'
            AND jsonb_typeof(request_parameters -> 'code_challenge') = 'string'
            AND request_parameters ->> 'code_challenge' ~ '^[A-Za-z0-9_-]{43}$'
            AND request_parameters ? 'code_challenge_method'
            AND jsonb_typeof(request_parameters -> 'code_challenge_method') = 'string'
            AND request_parameters ->> 'code_challenge_method' = 'S256'
            AND (
                NOT request_parameters ? 'nonce'
                OR (
                    jsonb_typeof(request_parameters -> 'nonce') = 'string'
                    AND char_length(request_parameters ->> 'nonce') BETWEEN 1 AND 255
                    AND request_parameters ->> 'nonce' ~ '^[!-~]+$'
                )
            )
            AND (
                NOT request_parameters ? 'prompt'
                OR (
                    jsonb_typeof(request_parameters -> 'prompt') = 'string'
                    AND char_length(request_parameters ->> 'prompt') BETWEEN 1 AND 128
                    AND request_parameters ->> 'prompt' ~ '^[A-Za-z_ -]+$'
                )
            )
            AND octet_length(request_parameters::text) <= 4096
        ),
    CONSTRAINT oauth_authorizations_uri_check
        CHECK (
            char_length(authorization_uri) BETWEEN 1 AND 2048
            AND authorization_uri ~ '^[!-~]+$'
            AND (
                redirect_uri IS NULL
                OR (
                    char_length(redirect_uri) BETWEEN 9 AND 2048
                    AND redirect_uri ~ '^[!-~]+$'
                )
            )
            AND (
                client_state IS NULL
                OR (
                    char_length(client_state) BETWEEN 1 AND 2048
                    AND client_state ~ '^[!-~]+$'
                )
            )
        ),
    CONSTRAINT oauth_authorizations_lifecycle_check
        CHECK (
            version >= 0
            AND updated_at >= created_at
            AND purge_at > updated_at
        )
);

CREATE INDEX oauth_authorizations_session_idx
    ON oauth_authorizations (tenant_id, user_id, session_id, authorization_id);

CREATE INDEX oauth_authorizations_purge_idx
    ON oauth_authorizations (purge_at, tenant_id, authorization_id);

CREATE INDEX oauth_authorizations_redirect_uri_idx
    ON oauth_authorizations (tenant_id, client_id, redirect_uri, authorization_id)
    WHERE redirect_uri IS NOT NULL;

CREATE TABLE oauth_authorization_requested_scopes (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    scope TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_authorization_requested_scopes_pkey
        PRIMARY KEY (tenant_id, client_id, authorization_id, scope),
    CONSTRAINT oauth_authorization_requested_scopes_authorization_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id)
        REFERENCES oauth_authorizations (tenant_id, client_id, authorization_id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_requested_scopes_client_scope_fk
        FOREIGN KEY (tenant_id, client_id, scope)
        REFERENCES oauth_client_scopes (tenant_id, client_id, scope) ON DELETE RESTRICT
);

CREATE TABLE oauth_authorization_scopes (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    scope TEXT COLLATE "C" NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_authorization_scopes_pkey
        PRIMARY KEY (tenant_id, client_id, authorization_id, scope),
    CONSTRAINT oauth_authorization_scopes_requested_scope_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id, scope)
        REFERENCES oauth_authorization_requested_scopes
            (tenant_id, client_id, authorization_id, scope) ON DELETE CASCADE
);

CREATE INDEX oauth_authorization_requested_scopes_client_scope_idx
    ON oauth_authorization_requested_scopes (tenant_id, client_id, scope, authorization_id);

CREATE TABLE oauth_authorization_principal_authorities (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    authority TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_authorization_principal_authorities_pkey
        PRIMARY KEY (tenant_id, client_id, authorization_id, authority),
    CONSTRAINT oauth_authorization_principal_authorities_authorization_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id)
        REFERENCES oauth_authorizations (tenant_id, client_id, authorization_id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_principal_authorities_value_check
        CHECK (
            char_length(authority) BETWEEN 1 AND 256
            AND authority ~ '^[!-~]+$'
        )
);

CREATE TABLE oauth_authorization_tokens (
    token_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    token_type TEXT NOT NULL,
    token_digest BYTEA NOT NULL,
    encryption_key_id TEXT COLLATE "C" NOT NULL,
    initialization_vector BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    access_token_type TEXT,
    claims_version SMALLINT,
    claims JSONB,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    invalidated_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_authorization_tokens_digest_key
        UNIQUE (token_digest),
    CONSTRAINT oauth_authorization_tokens_key_iv_key
        UNIQUE (encryption_key_id, initialization_vector),
    CONSTRAINT oauth_authorization_tokens_authorization_type_key
        UNIQUE (tenant_id, client_id, authorization_id, token_type),
    CONSTRAINT oauth_authorization_tokens_ownership_key
        UNIQUE (tenant_id, client_id, authorization_id, token_id, token_type),
    CONSTRAINT oauth_authorization_tokens_authorization_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id)
        REFERENCES oauth_authorizations (tenant_id, client_id, authorization_id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_tokens_type_check
        CHECK (token_type IN ('state', 'authorization_code', 'access_token', 'id_token')),
    CONSTRAINT oauth_authorization_tokens_protection_check
        CHECK (
            octet_length(token_digest) = 32
            AND char_length(encryption_key_id) BETWEEN 1 AND 64
            AND encryption_key_id ~ '^[A-Za-z0-9._-]+$'
            AND octet_length(initialization_vector) = 12
            AND octet_length(ciphertext) BETWEEN 17 AND 32768
        ),
    CONSTRAINT oauth_authorization_tokens_payload_check
        CHECK (
            (
                token_type = 'access_token'
                AND access_token_type IS NOT NULL
                AND access_token_type IN ('Bearer', 'DPoP')
            )
            OR (
                token_type <> 'access_token'
                AND access_token_type IS NULL
            )
        ),
    CONSTRAINT oauth_authorization_tokens_claims_check
        CHECK (
            (
                claims IS NULL
                AND claims_version IS NULL
                AND token_type IN ('state', 'authorization_code')
            )
            OR (
                claims IS NOT NULL
                AND claims_version IS NOT NULL
                AND claims_version = 1
                AND COALESCE(jsonb_typeof(claims) = 'object', false)
                AND token_type IN ('access_token', 'id_token')
                AND octet_length(claims::text) <= 32768
            )
        ),
    CONSTRAINT oauth_authorization_tokens_lifecycle_check
        CHECK (
            expires_at > issued_at
            AND created_at >= issued_at
            AND (
                invalidated_at IS NULL
                OR (
                    invalidated_at >= issued_at
                    AND updated_at >= invalidated_at
                )
            )
        ),
    CONSTRAINT oauth_authorization_tokens_version_timestamps_check
        CHECK (
            version >= 0
            AND updated_at >= created_at
        )
);

CREATE INDEX oauth_authorization_tokens_expiry_idx
    ON oauth_authorization_tokens (expires_at, tenant_id, token_id);

CREATE TABLE oauth_authorization_token_scopes (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_id UUID NOT NULL,
    token_id UUID NOT NULL,
    token_type TEXT NOT NULL DEFAULT 'access_token',
    scope TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_authorization_token_scopes_pkey
        PRIMARY KEY (tenant_id, client_id, authorization_id, token_id, scope),
    CONSTRAINT oauth_authorization_token_scopes_token_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id, token_id, token_type)
        REFERENCES oauth_authorization_tokens
            (tenant_id, client_id, authorization_id, token_id, token_type) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_token_scopes_client_scope_fk
        FOREIGN KEY (tenant_id, client_id, scope)
        REFERENCES oauth_client_scopes (tenant_id, client_id, scope) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_token_scopes_type_check
        CHECK (token_type = 'access_token')
);

CREATE INDEX oauth_authorization_token_scopes_client_scope_idx
    ON oauth_authorization_token_scopes
        (tenant_id, client_id, scope, authorization_id, token_id);

CREATE TABLE oauth_authorization_consents (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    principal_name TEXT COLLATE "C" NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_authorization_consents_pkey
        PRIMARY KEY (tenant_id, client_id, user_id),
    CONSTRAINT oauth_authorization_consents_lookup_key
        UNIQUE (client_id, principal_name),
    CONSTRAINT oauth_authorization_consents_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, client_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_consents_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_authorization_consents_identity_check
        CHECK (principal_name = user_id::text),
    CONSTRAINT oauth_authorization_consents_lifecycle_check
        CHECK (
            version >= 0
            AND updated_at >= created_at
        )
);

CREATE INDEX oauth_authorization_consents_user_idx
    ON oauth_authorization_consents (tenant_id, user_id, client_id);

CREATE TABLE oauth_authorization_consent_authorities (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    authority TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_authorization_consent_authorities_pkey
        PRIMARY KEY (tenant_id, client_id, user_id, authority),
    CONSTRAINT oauth_authorization_consent_authorities_consent_fk
        FOREIGN KEY (tenant_id, client_id, user_id)
        REFERENCES oauth_authorization_consents (tenant_id, client_id, user_id) ON DELETE CASCADE,
    CONSTRAINT oauth_authorization_consent_authorities_value_check
        CHECK (
            char_length(authority) BETWEEN 1 AND 256
            AND authority ~ '^[!-~]+$'
        )
);
