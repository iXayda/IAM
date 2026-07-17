ALTER TABLE oauth_clients
    ADD COLUMN refresh_tokens_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN refresh_token_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    ADD CONSTRAINT oauth_clients_refresh_token_ttl_check
        CHECK (refresh_token_ttl_seconds BETWEEN 300 AND 2592000),
    ADD CONSTRAINT oauth_clients_refresh_token_eligibility_check
        CHECK (
            NOT refresh_tokens_enabled
            OR (
                client_type = 'confidential'
                AND refresh_token_ttl_seconds > access_token_ttl_seconds
            )
        );

ALTER TABLE oauth_authorization_tokens
    DROP CONSTRAINT oauth_authorization_tokens_type_check;

ALTER TABLE oauth_authorization_tokens
    ADD CONSTRAINT oauth_authorization_tokens_type_check
        CHECK (token_type IN ('state', 'authorization_code', 'access_token', 'refresh_token', 'id_token'));

ALTER TABLE oauth_authorization_tokens
    DROP CONSTRAINT oauth_authorization_tokens_claims_check;

ALTER TABLE oauth_authorization_tokens
    ADD CONSTRAINT oauth_authorization_tokens_claims_check
        CHECK (
            (
                claims IS NULL
                AND claims_version IS NULL
                AND token_type IN ('state', 'authorization_code', 'refresh_token')
            )
            OR (
                claims IS NOT NULL
                AND claims_version IS NOT NULL
                AND claims_version = 1
                AND COALESCE(jsonb_typeof(claims) = 'object', false)
                AND token_type IN ('access_token', 'id_token')
                AND octet_length(claims::text) <= 32768
            )
        );
