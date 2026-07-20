ALTER TABLE oauth_authorization_principal_authorities
    ADD COLUMN issued_at TIMESTAMPTZ;

UPDATE oauth_authorization_principal_authorities authorities
SET issued_at = sessions.authenticated_at
FROM oauth_authorizations authorizations
JOIN user_sessions sessions
  ON sessions.tenant_id = authorizations.tenant_id
 AND sessions.session_id = authorizations.session_id
WHERE authorities.tenant_id = authorizations.tenant_id
  AND authorities.client_id = authorizations.client_id
  AND authorities.authorization_id = authorizations.authorization_id
  AND left(authorities.authority, 7) = 'FACTOR_';

ALTER TABLE oauth_authorization_principal_authorities
    ADD CONSTRAINT oauth_authorization_principal_authorities_factor_time_check
        CHECK (
            (
                left(authority, 7) = 'FACTOR_'
                AND issued_at IS NOT NULL
                AND issued_at >= TIMESTAMPTZ '1970-01-01 00:00:00+00'
            )
            OR (
                left(authority, 7) <> 'FACTOR_'
                AND issued_at IS NULL
            )
        );
