ALTER TABLE user_login_identifiers
    ADD CONSTRAINT user_login_identifiers_printable_email_check
        CHECK (
            identifier_type <> 'email'
            OR (identifier_value COLLATE "C") ~ '^[[:graph:]]+$'
        ),
    ADD CONSTRAINT user_login_identifiers_unambiguous_username_check
        CHECK (
            identifier_type <> 'username'
            OR identifier_value !~ '^[0-9.-]+$'
            OR regexp_replace(identifier_value, '[^0-9]', '', 'g') !~ '^[1-9][0-9]{5,14}$'
            OR canonical_value = regexp_replace(identifier_value, '[^0-9]', '', 'g')
        );
