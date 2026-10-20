\set ON_ERROR_STOP on
\if :{?runtime_role}
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Required psql variable: runtime_role'; END $$;
\endif
\if :{?iam_schema}
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Required psql variable: iam_schema'; END $$;
\endif

-- Run as the owner in a dedicated IAM database. Supply an existing, independent LOGIN role.
BEGIN;
SELECT current_user = pg_get_userbyid(datdba) AS is_owner
FROM pg_database WHERE datname = current_database() \gset
\if :is_owner
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Connect as the IAM database owner'; END $$;
\endif

SELECT EXISTS (
    SELECT 1 FROM pg_roles r WHERE r.rolname = :'runtime_role'
      AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
      AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit
      AND r.rolname <> current_user
      AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner = r.oid)
) AS safe_role \gset
\if :safe_role
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Runtime role must be an independent, unprivileged NOINHERIT LOGIN without ownership or role membership'; END $$;
\endif

SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = :'iam_schema')
    AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = :'iam_schema' AND c.relkind IN ('r','p','v','m','S','f')
          AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user)
    ) AS owned_schema \gset
\if :owned_schema
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Migrate the IAM schema with this owner first; all IAM relations must have the same owner'; END $$;
\endif

SELECT current_database() AS iam_database \gset
REVOKE ALL ON DATABASE :"iam_database" FROM PUBLIC, :"runtime_role";
GRANT CONNECT ON DATABASE :"iam_database" TO :"runtime_role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC, :"runtime_role";
REVOKE ALL ON SCHEMA :"iam_schema" FROM PUBLIC, :"runtime_role";
GRANT USAGE ON SCHEMA :"iam_schema" TO :"runtime_role";
REVOKE ALL ON ALL TABLES IN SCHEMA :"iam_schema" FROM PUBLIC, :"runtime_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA :"iam_schema" FROM PUBLIC, :"runtime_role";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :"iam_schema" FROM PUBLIC, :"runtime_role";

-- Table-level REVOKE does not remove column ACLs. Remove those before applying the allowlist.
SELECT format('REVOKE ALL (%s) ON TABLE %I.%I FROM PUBLIC, %I',
    string_agg(format('%I', a.attname), ', ' ORDER BY a.attnum), n.nspname, c.relname, :'runtime_role')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE n.nspname = :'iam_schema' AND c.relkind IN ('r','p','v','m','f')
GROUP BY n.nspname, c.relname ORDER BY c.relname \gexec

-- Future objects receive no automatic runtime grants; review this allowlist with each migration.
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM PUBLIC, :"runtime_role";
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC, :"runtime_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA :"iam_schema" REVOKE ALL ON TABLES FROM PUBLIC, :"runtime_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA :"iam_schema" REVOKE ALL ON SEQUENCES FROM PUBLIC, :"runtime_role";
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, :"runtime_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA :"iam_schema" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, :"runtime_role";

SET LOCAL search_path = :"iam_schema", pg_catalog;
GRANT SELECT, INSERT, UPDATE ON
    iam_user, iam_password, iam_user_setup, iam_password_recovery,
    iam_resource, iam_resource_role, iam_user_resource_role_revision,
    oauth2_registered_client, iam_client, oauth2_authorization, iam_authorization_record,
    iam_refresh_family, iam_refresh_history, iam_resource_credential
TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON
    iam_password_authentication_limit, iam_browser_session, iam_browser_session_attributes,
    iam_user_totp, iam_totp_authentication_limit, iam_mfa_recovery_code, iam_mfa_recovery_limit,
    iam_totp_recovery, iam_totp_replacement, iam_account_setup_limit, iam_password_recovery_limit,
    iam_user_role, iam_client_allowed_role, iam_authorization_token_index, iam_authorization_interaction
TO :"runtime_role";
GRANT SELECT, INSERT ON iam_authorization_binding, iam_authorization_binding_role TO :"runtime_role";
GRANT SELECT, INSERT ON iam_security_audit TO :"runtime_role";
GRANT SELECT ON iam_restore_release, iam_restore_administrator, iam_restore, iam_restore_state, iam_administrator, iam_admin_bootstrap, iam_signing_key, iam_signing_key_state TO :"runtime_role";
-- PostgreSQL row locks require UPDATE on at least one column, even without a mutation.
GRANT UPDATE (singleton) ON iam_signing_key_state TO :"runtime_role";
-- Last-administrator protection genuinely advances this revision during Web operations.
GRANT UPDATE (revision) ON iam_admin_bootstrap TO :"runtime_role";

-- Do not silently accept an effective CREATE privilege inherited through a different schema/PUBLIC.
SELECT NOT has_database_privilege(:'runtime_role', current_database(), 'CREATE,TEMPORARY')
    AND NOT EXISTS (
        SELECT 1 FROM pg_namespace WHERE has_schema_privilege(:'runtime_role', oid, 'CREATE')
    ) AS no_creation \gset
\if :no_creation
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Runtime still has database/schema creation privileges; remove the unrelated grants and retry'; END $$;
\endif
COMMIT;
\echo 'IAM runtime privileges applied'
