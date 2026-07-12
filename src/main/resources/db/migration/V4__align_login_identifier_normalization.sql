ALTER TABLE user_login_identifiers
    DROP CONSTRAINT user_login_identifiers_value_check;

ALTER TABLE users
    ADD CONSTRAINT users_last_login_check
        CHECK (last_login_at IS NULL OR last_login_at >= created_at);

ALTER TABLE user_login_identifiers
    ADD CONSTRAINT user_login_identifiers_value_check
        CHECK (
            identifier_value = btrim(identifier_value)
            AND char_length(identifier_value) BETWEEN 1 AND 254
            AND canonical_value = btrim(canonical_value)
            AND char_length(canonical_value) BETWEEN 1 AND 254
            AND (
                (identifier_type = 'username'
                    AND char_length(identifier_value) BETWEEN 3 AND 80
                    AND identifier_value ~ '^[A-Za-z0-9._:-]+$'
                    AND canonical_value = lower(identifier_value COLLATE "C"))
                OR (identifier_type = 'email'
                    AND char_length(identifier_value) BETWEEN 3 AND 254
                    AND octet_length(identifier_value) = char_length(identifier_value)
                    AND canonical_value = lower(identifier_value COLLATE "C")
                    AND canonical_value ~ '^[^@[:space:]]+@[^@[:space:]]+$')
                OR (identifier_type = 'phone'
                    AND char_length(identifier_value) BETWEEN 6 AND 32
                    AND identifier_value ~ '^\+?[0-9(). -]+$'
                    AND canonical_value = regexp_replace(identifier_value, '[^0-9]', '', 'g')
                    AND canonical_value ~ '^[1-9][0-9]{5,14}$')
            )
        );
