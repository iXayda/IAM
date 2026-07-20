CREATE TABLE user_recovery_codes (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    code_selector CHAR(5) NOT NULL,
    encoded_code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT user_recovery_codes_pkey
        PRIMARY KEY (tenant_id, user_id, code_selector),
    CONSTRAINT user_recovery_codes_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_recovery_codes_selector_check
        CHECK (
            octet_length(code_selector) = 5
            AND (code_selector COLLATE "C") ~ '^[0-9A-HJKMNP-TV-Z]{5}$'
        ),
    CONSTRAINT user_recovery_codes_encoding_check
        CHECK (
            char_length(encoded_code) BETWEEN 32 AND 1024
            AND octet_length(encoded_code) = char_length(encoded_code)
            AND (encoded_code COLLATE "C")
                ~ '^[{][A-Za-z0-9@._-]{1,64}[}][!-~]{20,}$'
            AND encoded_code !~* '^[{]noop[}]'
        ),
    CONSTRAINT user_recovery_codes_timestamps_check
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX user_recovery_codes_available_user_idx
    ON user_recovery_codes (tenant_id, user_id)
    WHERE consumed_at IS NULL;
