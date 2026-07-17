ALTER TABLE users
    ADD COLUMN display_name TEXT,
    ADD COLUMN formatted_name TEXT,
    ADD COLUMN given_name TEXT,
    ADD COLUMN family_name TEXT,
    ADD COLUMN security_version BIGINT;

UPDATE users
SET security_version = version;

ALTER TABLE users
    ALTER COLUMN security_version SET DEFAULT 0,
    ALTER COLUMN security_version SET NOT NULL,
    ADD CONSTRAINT users_security_version_check
        CHECK (security_version >= 0 AND security_version <= version),
    ADD CONSTRAINT users_profile_check
        CHECK (
            (display_name IS NULL OR (
                display_name !~ '^[[:space:]]|[[:space:]]$'
                AND char_length(display_name) BETWEEN 1 AND 200
                AND display_name !~ '[[:cntrl:]]'
            ))
            AND (formatted_name IS NULL OR (
                formatted_name !~ '^[[:space:]]|[[:space:]]$'
                AND char_length(formatted_name) BETWEEN 1 AND 200
                AND formatted_name !~ '[[:cntrl:]]'
            ))
            AND (given_name IS NULL OR (
                given_name !~ '^[[:space:]]|[[:space:]]$'
                AND char_length(given_name) BETWEEN 1 AND 200
                AND given_name !~ '[[:cntrl:]]'
            ))
            AND (family_name IS NULL OR (
                family_name !~ '^[[:space:]]|[[:space:]]$'
                AND char_length(family_name) BETWEEN 1 AND 200
                AND family_name !~ '[[:cntrl:]]'
            ))
        );
