UPDATE oauth_clients
SET access_token_ttl_seconds = 300
WHERE authorization_grant_type = 'client_credentials'
  AND access_token_ttl_seconds > 300;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_service_token_policy_check
        CHECK (
            authorization_grant_type <> 'client_credentials'
            OR (
                access_token_ttl_seconds BETWEEN 60 AND 300
                AND NOT refresh_tokens_enabled
            )
        );

ALTER TABLE oauth_client_scopes
    DROP CONSTRAINT oauth_client_scopes_client_fk,
    ADD COLUMN authorization_grant_type TEXT;

UPDATE oauth_client_scopes scopes
SET authorization_grant_type = clients.authorization_grant_type
FROM oauth_clients clients
WHERE clients.tenant_id = scopes.tenant_id
  AND clients.client_id = scopes.client_id;

DELETE FROM oauth_authorizations authorizations
USING oauth_clients clients
WHERE authorizations.tenant_id = clients.tenant_id
  AND authorizations.client_id = clients.client_id
  AND authorizations.authorization_grant_type = 'client_credentials'
  AND clients.authorization_grant_type = 'client_credentials'
  AND EXISTS (
      SELECT 1
      FROM oauth_client_scopes scopes
      WHERE scopes.tenant_id = clients.tenant_id
        AND scopes.client_id = clients.client_id
        AND scopes.scope IN ('openid', 'offline_access', 'profile', 'email', 'address', 'phone')
  );

DELETE FROM oauth_client_scopes
WHERE authorization_grant_type = 'client_credentials'
  AND scope IN ('openid', 'offline_access', 'profile', 'email', 'address', 'phone');

UPDATE oauth_clients clients
SET status = 'disabled',
    version = version + 1,
    updated_at = GREATEST(updated_at, now())
WHERE authorization_grant_type = 'client_credentials'
  AND status = 'active'
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_client_scopes scopes
      WHERE scopes.tenant_id = clients.tenant_id
        AND scopes.client_id = clients.client_id
  );

ALTER TABLE oauth_client_scopes
    ALTER COLUMN authorization_grant_type SET NOT NULL,
    ALTER COLUMN authorization_grant_type SET DEFAULT 'authorization_code',
    ADD CONSTRAINT oauth_client_scopes_authorization_grant_type_check
        CHECK (authorization_grant_type IN ('authorization_code', 'client_credentials')),
    ADD CONSTRAINT oauth_client_scopes_service_scope_check
        CHECK (
            authorization_grant_type = 'authorization_code'
            OR scope NOT IN ('openid', 'offline_access', 'profile', 'email', 'address', 'phone')
        ),
    ADD CONSTRAINT oauth_client_scopes_client_fk
        FOREIGN KEY (tenant_id, client_id, authorization_grant_type)
        REFERENCES oauth_clients (tenant_id, client_id, authorization_grant_type) ON DELETE CASCADE;
