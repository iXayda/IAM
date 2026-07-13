CREATE TABLE user_external_identities (
    tenant_id UUID NOT NULL,
    provider_id TEXT COLLATE "C" NOT NULL,
    subject_id TEXT COLLATE "C" NOT NULL,
    user_id UUID NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_external_identities_pkey
        PRIMARY KEY (tenant_id, provider_id, subject_id),
    CONSTRAINT user_external_identities_user_provider_key
        UNIQUE (tenant_id, user_id, provider_id),
    CONSTRAINT user_external_identities_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT user_external_identities_provider_check
        CHECK (
            char_length(provider_id) BETWEEN 1 AND 64
            AND provider_id ~ '^[a-z]([a-z0-9-]{0,62}[a-z0-9])?$'
        ),
    CONSTRAINT user_external_identities_subject_check
        CHECK (
            char_length(subject_id) BETWEEN 1 AND 512
            AND octet_length(subject_id) = char_length(subject_id)
            AND subject_id ~ '^[!-~]+$'
        )
);
