CREATE INDEX users_tenant_directory_page_idx
    ON users (tenant_id, user_id)
    WHERE status <> 'deleted';

CREATE INDEX user_login_identifiers_tenant_phone_value_idx
    ON user_login_identifiers (tenant_id, identifier_value, user_id)
    WHERE identifier_type = 'phone';
