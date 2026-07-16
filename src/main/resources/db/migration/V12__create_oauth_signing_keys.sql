CREATE TABLE oauth_signing_keys (
    signing_key_id UUID PRIMARY KEY,
    kid TEXT COLLATE "C" NOT NULL,
    key_type TEXT COLLATE "C" NOT NULL,
    key_use TEXT COLLATE "C" NOT NULL,
    signature_algorithm TEXT COLLATE "C" NOT NULL,
    public_modulus BYTEA NOT NULL,
    public_exponent INTEGER NOT NULL,
    status TEXT COLLATE "C" NOT NULL,
    attestation_version SMALLINT NOT NULL,
    attestation_key_id TEXT COLLATE "C" NOT NULL,
    attestation_tag BYTEA NOT NULL,
    private_key_format TEXT COLLATE "C",
    protection_version SMALLINT,
    encryption_key_id TEXT COLLATE "C",
    initialization_vector BYTEA,
    private_key_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activate_after TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    publish_until TIMESTAMPTZ,
    private_key_destroyed_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_signing_keys_kid_key
        UNIQUE (kid),
    CONSTRAINT oauth_signing_keys_public_key_key
        UNIQUE (public_modulus, public_exponent),
    CONSTRAINT oauth_signing_keys_encryption_key_iv_key
        UNIQUE (encryption_key_id, initialization_vector),
    CONSTRAINT oauth_signing_keys_identity_check
        CHECK (
            char_length(kid) = 43
            AND octet_length(kid) = 43
            AND kid ~ '^[A-Za-z0-9_-]{43}$'
            AND key_type = 'RSA'
            AND key_use = 'sig'
            AND signature_algorithm = 'RS256'
        ),
    CONSTRAINT oauth_signing_keys_public_material_check
        CHECK (
            octet_length(public_modulus) = 384
            AND CASE
                WHEN octet_length(public_modulus) = 384 THEN
                    get_byte(public_modulus, 0) >= 128
                    AND get_byte(public_modulus, 383) % 2 = 1
                ELSE false
            END
            AND public_exponent = 65537
        ),
    CONSTRAINT oauth_signing_keys_status_check
        CHECK (status IN ('staged', 'active', 'retired')),
    CONSTRAINT oauth_signing_keys_attestation_check
        CHECK (
            attestation_version = 1
            AND char_length(attestation_key_id) BETWEEN 1 AND 64
            AND attestation_key_id ~ '^[A-Za-z0-9._-]+$'
            AND octet_length(attestation_tag) = 32
        ),
    CONSTRAINT oauth_signing_keys_private_material_check
        CHECK (
            (
                private_key_format IS NULL
                AND protection_version IS NULL
                AND encryption_key_id IS NULL
                AND initialization_vector IS NULL
                AND private_key_ciphertext IS NULL
            )
            OR (
                private_key_format IS NOT NULL
                AND private_key_format = 'PKCS8'
                AND protection_version IS NOT NULL
                AND protection_version = 1
                AND encryption_key_id IS NOT NULL
                AND char_length(encryption_key_id) BETWEEN 1 AND 64
                AND encryption_key_id ~ '^[A-Za-z0-9._-]+$'
                AND initialization_vector IS NOT NULL
                AND octet_length(initialization_vector) = 12
                AND private_key_ciphertext IS NOT NULL
                AND octet_length(private_key_ciphertext) BETWEEN 1024 AND 8192
            )
        ),
    CONSTRAINT oauth_signing_keys_lifecycle_check
        CHECK (
            created_at <= published_at
            AND published_at <= activate_after
            AND (
                (
                    status = 'staged'
                    AND private_key_ciphertext IS NOT NULL
                    AND activated_at IS NULL
                    AND retired_at IS NULL
                    AND publish_until IS NULL
                    AND private_key_destroyed_at IS NULL
                    AND updated_at >= published_at
                )
                OR (
                    status = 'active'
                    AND private_key_ciphertext IS NOT NULL
                    AND activated_at IS NOT NULL
                    AND activated_at >= activate_after
                    AND retired_at IS NULL
                    AND publish_until IS NULL
                    AND private_key_destroyed_at IS NULL
                    AND updated_at >= activated_at
                )
                OR (
                    status = 'retired'
                    AND private_key_ciphertext IS NULL
                    AND activated_at IS NOT NULL
                    AND activated_at >= activate_after
                    AND retired_at IS NOT NULL
                    AND retired_at >= activated_at
                    AND publish_until IS NOT NULL
                    AND publish_until > retired_at
                    AND private_key_destroyed_at IS NOT NULL
                    AND private_key_destroyed_at >= retired_at
                    AND publish_until > private_key_destroyed_at
                    AND updated_at >= private_key_destroyed_at
                )
            )
        ),
    CONSTRAINT oauth_signing_keys_version_timestamps_check
        CHECK (version >= 0 AND updated_at >= created_at)
);

CREATE UNIQUE INDEX oauth_signing_keys_single_staged_idx
    ON oauth_signing_keys ((1))
    WHERE status = 'staged';

CREATE UNIQUE INDEX oauth_signing_keys_single_active_idx
    ON oauth_signing_keys ((1))
    WHERE status = 'active';

CREATE INDEX oauth_signing_keys_retired_publication_idx
    ON oauth_signing_keys (publish_until, signing_key_id)
    WHERE status = 'retired';
