package com.ixayda.iam.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Reads effective PostgreSQL capabilities, including PUBLIC and column privileges. */
@Repository
public class IdentityDatabaseAccessRepository {

	private final JdbcClient jdbc;

	IdentityDatabaseAccessRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

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
				        SELECT 1 FROM (VALUES ('iam_signing_key'),('iam_administrator'),('iam_signing_key_state'),('iam_admin_bootstrap'),('iam_restore'),('iam_restore_state'),('iam_restore_administrator')) AS t(name)
				        WHERE has_table_privilege(t.name,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
				           OR has_any_column_privilege(t.name,'INSERT')
				    )
				    AND NOT EXISTS (
				        SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
				        WHERE n.nspname=current_schema() AND a.attnum>0 AND NOT a.attisdropped
				          AND (c.relname IN ('iam_signing_key','iam_administrator','iam_restore','iam_restore_state','iam_restore_administrator')
				               OR c.relname='iam_signing_key_state' AND a.attname<>'singleton'
				               OR c.relname='iam_admin_bootstrap' AND a.attname<>'revision')
				          AND has_column_privilege(c.oid,a.attnum,'UPDATE')
				    )
				    AND NOT has_any_column_privilege('iam_administrator_recovery','SELECT,INSERT,UPDATE,REFERENCES')
				    AND NOT has_table_privilege('iam_administrator_recovery','DELETE,TRUNCATE,TRIGGER,MAINTAIN')
				    AND NOT has_any_column_privilege('flyway_schema_history','SELECT,INSERT,UPDATE,REFERENCES')
				    AND NOT has_table_privilege('flyway_schema_history','DELETE,TRUNCATE,TRIGGER,MAINTAIN')
				FROM pg_roles r WHERE r.rolname=current_user
				""").query(Boolean.class).single();
	}
}
