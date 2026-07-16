CREATE TABLE oauth_clients (
    client_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    client_identifier TEXT COLLATE "C" NOT NULL,
    display_name TEXT NOT NULL,
    client_type TEXT NOT NULL,
    authentication_method TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    encoded_client_secret TEXT,
    client_secret_issued_at TIMESTAMPTZ,
    client_secret_expires_at TIMESTAMPTZ,
    authorization_code_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    access_token_ttl_seconds INTEGER NOT NULL DEFAULT 300,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_clients_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT oauth_clients_tenant_client_key
        UNIQUE (tenant_id, client_id),
    CONSTRAINT oauth_clients_client_identifier_key
        UNIQUE (client_identifier),
    CONSTRAINT oauth_clients_identifier_check
        CHECK (
            char_length(client_identifier) BETWEEN 1 AND 128
            AND octet_length(client_identifier) = char_length(client_identifier)
            AND client_identifier ~ '^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$'
        ),
    CONSTRAINT oauth_clients_display_name_check
        CHECK (
            display_name = btrim(display_name)
            AND char_length(display_name) BETWEEN 1 AND 200
        ),
    CONSTRAINT oauth_clients_type_check
        CHECK (client_type IN ('public', 'confidential')),
    CONSTRAINT oauth_clients_authentication_method_check
        CHECK (authentication_method IN ('none', 'client_secret_basic')),
    CONSTRAINT oauth_clients_status_check
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_clients_secret_format_check
        CHECK (
            encoded_client_secret IS NULL
            OR (
                char_length(encoded_client_secret) BETWEEN 32 AND 1024
                AND octet_length(encoded_client_secret) = char_length(encoded_client_secret)
                AND (encoded_client_secret COLLATE "C")
                    ~ '^[{][A-Za-z0-9@._-]{1,64}[}][!-~]{20,}$'
                AND encoded_client_secret !~* '^[{]noop[}]'
            )
        ),
    CONSTRAINT oauth_clients_secret_lifecycle_check
        CHECK (
            (
                client_type = 'public'
                AND authentication_method = 'none'
                AND encoded_client_secret IS NULL
                AND client_secret_issued_at IS NULL
                AND client_secret_expires_at IS NULL
            )
            OR (
                client_type = 'confidential'
                AND authentication_method = 'client_secret_basic'
                AND encoded_client_secret IS NOT NULL
                AND client_secret_issued_at IS NOT NULL
                AND client_secret_expires_at IS NOT NULL
                AND client_secret_issued_at >= created_at
                AND client_secret_issued_at <= updated_at
                AND client_secret_expires_at > client_secret_issued_at
            )
        ),
    CONSTRAINT oauth_clients_token_ttl_check
        CHECK (
            authorization_code_ttl_seconds BETWEEN 30 AND 600
            AND access_token_ttl_seconds BETWEEN 60 AND 3600
        ),
    CONSTRAINT oauth_clients_version_check
        CHECK (version >= 0),
    CONSTRAINT oauth_clients_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE INDEX oauth_clients_tenant_status_idx
    ON oauth_clients (tenant_id, status, client_id);

CREATE TABLE oauth_client_redirect_uris (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    redirect_uri TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_client_redirect_uris_pkey
        PRIMARY KEY (tenant_id, client_id, redirect_uri),
    CONSTRAINT oauth_client_redirect_uris_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, client_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_redirect_uris_value_check
        CHECK (
            char_length(redirect_uri) BETWEEN 9 AND 2048
            AND octet_length(redirect_uri) = char_length(redirect_uri)
            AND redirect_uri ~ '^[!-~]+$'
            AND lower(left(redirect_uri, 8)) = 'https://'
            AND strpos(redirect_uri, '#') = 0
            AND strpos(redirect_uri, '*') = 0
            AND strpos(redirect_uri, '"') = 0
            AND strpos(redirect_uri, chr(92)) = 0
        )
);

CREATE TABLE oauth_client_post_logout_redirect_uris (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    post_logout_redirect_uri TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_client_post_logout_redirect_uris_pkey
        PRIMARY KEY (tenant_id, client_id, post_logout_redirect_uri),
    CONSTRAINT oauth_client_post_logout_redirect_uris_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, client_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_post_logout_redirect_uris_value_check
        CHECK (
            char_length(post_logout_redirect_uri) BETWEEN 9 AND 2048
            AND octet_length(post_logout_redirect_uri) = char_length(post_logout_redirect_uri)
            AND post_logout_redirect_uri ~ '^[!-~]+$'
            AND lower(left(post_logout_redirect_uri, 8)) = 'https://'
            AND strpos(post_logout_redirect_uri, '#') = 0
            AND strpos(post_logout_redirect_uri, '*') = 0
            AND strpos(post_logout_redirect_uri, '"') = 0
            AND strpos(post_logout_redirect_uri, chr(92)) = 0
        )
);

CREATE TABLE oauth_client_scopes (
    tenant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    scope TEXT COLLATE "C" NOT NULL,
    CONSTRAINT oauth_client_scopes_pkey
        PRIMARY KEY (tenant_id, client_id, scope),
    CONSTRAINT oauth_client_scopes_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth_clients (tenant_id, client_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_scopes_value_check
        CHECK (
            char_length(scope) BETWEEN 1 AND 128
            AND octet_length(scope) = char_length(scope)
            AND scope ~ '^[!-~]+$'
            AND strpos(scope, '"') = 0
            AND strpos(scope, chr(92)) = 0
            AND scope <> 'offline_access'
        )
);
