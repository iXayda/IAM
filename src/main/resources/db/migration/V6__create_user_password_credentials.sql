CREATE TABLE user_password_credentials (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    encoded_password TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_password_credentials_pkey
        PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT user_password_credentials_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_password_credentials_encoded_password_check
        CHECK (
            char_length(encoded_password) BETWEEN 32 AND 1024
            AND octet_length(encoded_password) = char_length(encoded_password)
            AND (encoded_password COLLATE "C")
                ~ '^[{][A-Za-z0-9@._-]{1,64}[}][!-~]{20,}$'
            AND encoded_password !~* '^[{]noop[}]'
        ),
    CONSTRAINT user_password_credentials_version_check
        CHECK (version >= 0),
    CONSTRAINT user_password_credentials_timestamps_check
        CHECK (updated_at >= created_at)
);
