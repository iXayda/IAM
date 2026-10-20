package com.ixayda.iam.repository;

import java.util.Optional;

import javax.sql.DataSource;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Reads effective PostgreSQL capabilities, including PUBLIC and column privileges. */
@Repository
public class IdentityDatabaseAccessRepository {

	private final JdbcClient jdbc;

	IdentityDatabaseAccessRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public static void requireMaintenanceOwner(DataSource dataSource) {
		boolean owner = JdbcClient.create(dataSource).sql("""
				SELECT current_user = session_user AND current_user = pg_catalog.pg_get_userbyid(datdba)
				FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()
				""").query(Boolean.class).single();
		if (!owner) { throw new IllegalStateException("Maintenance requires the database owner"); }
	}

	/** Bind maintenance metadata to the exact relations resolved by the business connection's search path. */
	public Optional<String> maintenanceSchema() {
		return this.jdbc.sql("""
				SELECT n.nspname FROM pg_class gate JOIN pg_namespace n ON n.oid=gate.relnamespace
				WHERE gate.oid=to_regclass('iam_signing_key_state') AND gate.relkind IN ('r','p')
				AND NOT EXISTS (
				    SELECT 1 FROM pg_class business
				    WHERE business.relnamespace=n.oid AND business.relkind IN ('r','p')
				      AND (left(business.relname,4)='iam_' OR left(business.relname,7)='oauth2_')
				      AND to_regclass(quote_ident(business.relname)) IS DISTINCT FROM business.oid
				)
				""").query(String.class).optional();
	}

	public boolean isRestrictedRuntime() {
		return this.jdbc.sql("""
				SELECT current_user = session_user AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole
				    AND NOT r.rolinherit AND NOT r.rolreplication AND NOT r.rolbypassrls
				    AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid)
				    AND NOT EXISTS (SELECT 1 FROM pg_database WHERE datdba=r.oid)
				    AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner=r.oid OR has_schema_privilege(r.oid,oid,'CREATE'))
				    AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relowner=r.oid)
				    AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE proowner=r.oid)
				    AND NOT has_database_privilege(current_database(),'CREATE,TEMPORARY')
				    AND NOT has_table_privilege('iam_security_audit','UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
				    AND NOT has_any_column_privilege('iam_security_audit','UPDATE')
				    AND NOT EXISTS (
				        SELECT 1 FROM (VALUES ('iam_authorization_protection'),('iam_signing_key'),('iam_administrator'),('iam_signing_key_state'),('iam_admin_bootstrap'),('iam_restore'),('iam_restore_state')) AS t(name)
				        WHERE has_table_privilege(t.name,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
				           OR has_any_column_privilege(t.name,'INSERT')
				    )
				    AND NOT EXISTS (
				        SELECT 1 FROM (VALUES
				            ('iam_authorization_protection',NULL),('iam_signing_key',NULL),('iam_administrator',NULL),
				            ('iam_restore',NULL),('iam_restore_state',NULL),('iam_signing_key_state','singleton'),('iam_admin_bootstrap','revision')
				        ) AS protected(name,allowed_update_column)
				        JOIN pg_attribute a ON a.attrelid=to_regclass(protected.name)
				        WHERE a.attnum>0 AND NOT a.attisdropped
				          AND (protected.allowed_update_column IS NULL OR a.attname<>protected.allowed_update_column)
				          AND has_column_privilege(a.attrelid,a.attnum,'UPDATE')
				    )
				    AND NOT has_any_column_privilege('iam_administrator_recovery','SELECT,INSERT,UPDATE,REFERENCES')
				    AND NOT has_table_privilege('iam_administrator_recovery','DELETE,TRUNCATE,TRIGGER,MAINTAIN')
				    AND NOT has_any_column_privilege('flyway_schema_history','SELECT,INSERT,UPDATE,REFERENCES')
				    AND NOT has_table_privilege('flyway_schema_history','DELETE,TRUNCATE,TRIGGER,MAINTAIN')
				FROM pg_roles r WHERE r.rolname=current_user
				""").query(Boolean.class).single();
	}
}
