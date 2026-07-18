ALTER TABLE oauth_clients
    ADD COLUMN authorization_grant_type TEXT NOT NULL DEFAULT 'authorization_code',
    ADD CONSTRAINT oauth_clients_authorization_grant_type_check
        CHECK (authorization_grant_type IN ('authorization_code', 'client_credentials')),
    ADD CONSTRAINT oauth_clients_authorization_grant_eligibility_check
        CHECK (
            authorization_grant_type = 'authorization_code'
            OR (
                authorization_grant_type = 'client_credentials'
                AND client_type = 'confidential'
                AND authentication_method = 'client_secret_basic'
            )
        ),
    ADD CONSTRAINT oauth_clients_tenant_client_grant_key
        UNIQUE (tenant_id, client_id, authorization_grant_type),
    ADD CONSTRAINT oauth_clients_tenant_client_identifier_grant_key
        UNIQUE (tenant_id, client_id, client_identifier, authorization_grant_type);

ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_refresh_token_eligibility_check,
    ADD CONSTRAINT oauth_clients_refresh_token_eligibility_check
        CHECK (
            NOT refresh_tokens_enabled
            OR (
                client_type = 'confidential'
                AND authorization_grant_type = 'authorization_code'
                AND refresh_token_ttl_seconds > access_token_ttl_seconds
            )
        );

ALTER TABLE oauth_client_redirect_uris
    DROP CONSTRAINT oauth_client_redirect_uris_client_fk,
    ADD COLUMN authorization_grant_type TEXT NOT NULL DEFAULT 'authorization_code',
    ADD CONSTRAINT oauth_client_redirect_uris_authorization_grant_type_check
        CHECK (authorization_grant_type = 'authorization_code'),
    ADD CONSTRAINT oauth_client_redirect_uris_client_fk
        FOREIGN KEY (tenant_id, client_id, authorization_grant_type)
        REFERENCES oauth_clients (tenant_id, client_id, authorization_grant_type) ON DELETE CASCADE;

ALTER TABLE oauth_client_post_logout_redirect_uris
    DROP CONSTRAINT oauth_client_post_logout_redirect_uris_client_fk,
    ADD COLUMN authorization_grant_type TEXT NOT NULL DEFAULT 'authorization_code',
    ADD CONSTRAINT oauth_post_logout_redirect_uris_grant_check
        CHECK (authorization_grant_type = 'authorization_code'),
    ADD CONSTRAINT oauth_client_post_logout_redirect_uris_client_fk
        FOREIGN KEY (tenant_id, client_id, authorization_grant_type)
        REFERENCES oauth_clients (tenant_id, client_id, authorization_grant_type) ON DELETE CASCADE;

ALTER TABLE oauth_authorizations
    DROP CONSTRAINT oauth_authorizations_client_fk,
    DROP CONSTRAINT oauth_authorizations_identity_check,
    DROP CONSTRAINT oauth_authorizations_grant_check,
    DROP CONSTRAINT oauth_authorizations_request_check,
    DROP CONSTRAINT oauth_authorizations_uri_check,
    ALTER COLUMN user_id DROP NOT NULL,
    ALTER COLUMN session_id DROP NOT NULL,
    ALTER COLUMN authorization_uri DROP NOT NULL,
    ADD CONSTRAINT oauth_authorizations_tenant_client_authorization_grant_key
        UNIQUE (tenant_id, client_id, authorization_id, authorization_grant_type),
    ADD CONSTRAINT oauth_authorizations_client_fk
        FOREIGN KEY (tenant_id, client_id, client_identifier, authorization_grant_type)
        REFERENCES oauth_clients
            (tenant_id, client_id, client_identifier, authorization_grant_type) ON DELETE RESTRICT,
    ADD CONSTRAINT oauth_authorizations_identity_check
        CHECK (
            char_length(client_identifier) BETWEEN 1 AND 128
            AND octet_length(client_identifier) = char_length(client_identifier)
            AND client_identifier ~ '^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$'
            AND (
                (
                    authorization_grant_type = 'authorization_code'
                    AND user_id IS NOT NULL
                    AND session_id IS NOT NULL
                    AND principal_name = user_id::text
                )
                OR (
                    authorization_grant_type = 'client_credentials'
                    AND user_id IS NULL
                    AND session_id IS NULL
                    AND principal_name = client_identifier
                )
            )
        ),
    ADD CONSTRAINT oauth_authorizations_grant_check
        CHECK (authorization_grant_type IN ('authorization_code', 'client_credentials')),
    ADD CONSTRAINT oauth_authorizations_request_check
        CHECK (
            request_version = 1
            AND jsonb_typeof(request_parameters) = 'object'
            AND octet_length(request_parameters::text) <= 4096
            AND (
                (
                    authorization_grant_type = 'authorization_code'
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
                )
                OR (
                    authorization_grant_type = 'client_credentials'
                    AND request_parameters = '{}'::jsonb
                )
            )
        ),
    ADD CONSTRAINT oauth_authorizations_uri_check
        CHECK (
            (
                authorization_grant_type = 'authorization_code'
                AND authorization_uri IS NOT NULL
                AND char_length(authorization_uri) BETWEEN 1 AND 2048
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
            )
            OR (
                authorization_grant_type = 'client_credentials'
                AND authorization_uri IS NULL
                AND redirect_uri IS NULL
                AND client_state IS NULL
            )
        );

ALTER TABLE oauth_authorization_tokens
    DROP CONSTRAINT oauth_authorization_tokens_authorization_fk,
    DROP CONSTRAINT oauth_authorization_tokens_type_check,
    ADD COLUMN authorization_grant_type TEXT NOT NULL DEFAULT 'authorization_code',
    ADD CONSTRAINT oauth_authorization_tokens_authorization_fk
        FOREIGN KEY (tenant_id, client_id, authorization_id, authorization_grant_type)
        REFERENCES oauth_authorizations
            (tenant_id, client_id, authorization_id, authorization_grant_type) ON DELETE CASCADE,
    ADD CONSTRAINT oauth_authorization_tokens_type_check
        CHECK (
            (
                authorization_grant_type = 'authorization_code'
                AND token_type IN ('state', 'authorization_code', 'access_token', 'refresh_token', 'id_token')
            )
            OR (
                authorization_grant_type = 'client_credentials'
                AND token_type = 'access_token'
            )
        );
