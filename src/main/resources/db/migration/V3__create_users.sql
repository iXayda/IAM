CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    CONSTRAINT users_tenant_fk
        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id) ON DELETE RESTRICT,
    CONSTRAINT users_tenant_user_key
        UNIQUE (tenant_id, user_id),
    CONSTRAINT users_status_check
        CHECK (status IN ('active', 'disabled', 'locked', 'deleted')),
    CONSTRAINT users_version_check
        CHECK (version >= 0),
    CONSTRAINT users_timestamps_check
        CHECK (updated_at >= created_at)
);

CREATE INDEX users_tenant_status_idx
    ON users (tenant_id, status, user_id);

CREATE TABLE user_login_identifiers (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    canonical_value TEXT COLLATE "C" NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_login_identifiers_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_login_identifiers_pkey
        PRIMARY KEY (tenant_id, user_id, identifier_type),
    CONSTRAINT user_login_identifiers_tenant_canonical_key
        UNIQUE (tenant_id, canonical_value),
    CONSTRAINT user_login_identifiers_type_check
        CHECK (identifier_type IN ('username', 'email', 'phone')),
    CONSTRAINT user_login_identifiers_value_check
        CHECK (
            identifier_value = btrim(identifier_value)
            AND char_length(identifier_value) BETWEEN 1 AND 254
            AND canonical_value = btrim(canonical_value)
            AND char_length(canonical_value) BETWEEN 1 AND 254
            AND (
                (identifier_type = 'username'
                    AND char_length(identifier_value) BETWEEN 3 AND 80
                    AND identifier_value ~ '^[A-Za-z0-9._:-]+$'
                    AND canonical_value = lower(identifier_value))
                OR (identifier_type = 'email'
                    AND char_length(identifier_value) BETWEEN 3 AND 254
                    AND octet_length(identifier_value) = char_length(identifier_value)
                    AND canonical_value = lower(identifier_value)
                    AND canonical_value ~ '^[^@[:space:]]+@[^@[:space:]]+$')
                OR (identifier_type = 'phone'
                    AND char_length(identifier_value) BETWEEN 6 AND 32
                    AND identifier_value ~ '^\+?[0-9().[:space:]-]+$'
                    AND canonical_value = regexp_replace(identifier_value, '[^0-9]', '', 'g')
                    AND canonical_value ~ '^[1-9][0-9]{5,14}$')
            )
        ),
    CONSTRAINT user_login_identifiers_timestamps_check
        CHECK (updated_at >= created_at)
);
