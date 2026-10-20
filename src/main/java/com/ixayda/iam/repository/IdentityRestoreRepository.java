package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestore;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Owner-only bulk containment. Table locks and transactional TRUNCATE are deliberate offline operations. */
@Repository
public class IdentityRestoreRepository {

	private static final List<String> INVALIDATED_TABLES = List.of(
			"iam_password", "iam_user_setup", "iam_password_recovery", "iam_user_totp", "iam_mfa_recovery_code",
			"iam_totp_recovery", "iam_totp_replacement", "iam_administrator_recovery", "iam_administrator",
			"iam_browser_session_attributes", "iam_browser_session", "iam_authorization_interaction",
			"iam_refresh_history", "iam_refresh_family", "iam_authorization_binding_role", "iam_authorization_binding",
			"iam_authorization_token_index", "iam_authorization_record", "oauth2_authorization",
			"iam_user_role", "iam_client_allowed_role");
	private static final String DISABLED_REDIRECT = "https://quarantine.invalid/callback";
	private final JdbcClient jdbc;

	IdentityRestoreRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public String databaseName() { return this.jdbc.sql("SELECT current_database()").query(String.class).single(); }

	public boolean isAvailable() {
		return this.jdbc.sql("""
				SELECT s.current_restore_id IS NULL OR EXISTS (
				    SELECT 1 FROM iam_restore_release l JOIN iam_restore_administrator a ON a.restore_id=l.restore_id
				    WHERE l.restore_id=s.current_restore_id AND l.user_id=a.user_id AND l.factor_id=a.factor_id
				        AND a.completed_at IS NOT NULL AND l.released_at>=a.completed_at)
				FROM iam_restore_state s WHERE s.singleton=1
				""").query(Boolean.class).single();
	}

	public void requireOfflineOwner(String expectedDatabase) {
		// Ordinary autovacuum is coordinated by the table locks; all other or unidentifiable backends still block restore.
		boolean allowed = this.jdbc.sql("""
				SELECT current_database()=:database AND current_user=session_user AND current_user=pg_get_userbyid(datdba)
				    AND NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datid=d.oid AND pid<>pg_backend_pid()
				        AND backend_type IS DISTINCT FROM 'autovacuum worker')
				FROM pg_database d WHERE datname=current_database()
				""").param("database", expectedDatabase).query(Boolean.class).single();
		if (!allowed) { throw new IllegalStateException("Restore requires the confirmed database owner and no other database clients"); }
	}

	public void lockForQuarantine() {
		this.jdbc.sql("SELECT set_config('lock_timeout','5s',true)").query(String.class).single();
		this.jdbc.sql("LOCK TABLE iam_restore_state, iam_restore, iam_restore_administrator, iam_restore_release, iam_signing_key_state, iam_signing_key, iam_user, iam_admin_bootstrap, "
				+ "iam_resource, iam_resource_role, iam_user_resource_role_revision, iam_client, oauth2_registered_client, iam_resource_credential, "
				+ "iam_security_audit, " + String.join(", ", INVALIDATED_TABLES) + " IN ACCESS EXCLUSIVE MODE").update();
	}

	public Optional<IdentityRestore> current() {
		return this.jdbc.sql("SELECT r.* FROM iam_restore r JOIN iam_restore_state s ON s.current_restore_id=r.id WHERE s.singleton=1")
				.query((row, index) -> restore(row)).optional();
	}

	public IdentityRestore recordSnapshot(UUID id, String checksum) {
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_restore(id,archive_sha256,database_name,snapshot_audit_count,snapshot_last_audit_at,snapshot_last_audit_id)
				SELECT :id,:checksum,current_database(),(SELECT count(*) FROM iam_security_audit),
				    (SELECT recorded_at FROM iam_security_audit ORDER BY recorded_at DESC,id DESC LIMIT 1),
				    (SELECT id FROM iam_security_audit ORDER BY recorded_at DESC,id DESC LIMIT 1)
				""").param("id", id).param("checksum", checksum).update());
		var stored = this.jdbc.sql("SELECT * FROM iam_restore WHERE id=:id").param("id", id).query((row, index) -> restore(row)).single();
		boolean accurate = this.jdbc.sql("""
				SELECT archive_sha256=:checksum AND database_name=current_database() AND snapshot_audit_count=(SELECT count(*) FROM iam_security_audit)
				    AND snapshot_last_audit_at IS NOT DISTINCT FROM (SELECT recorded_at FROM iam_security_audit ORDER BY recorded_at DESC,id DESC LIMIT 1)
				    AND snapshot_last_audit_id IS NOT DISTINCT FROM (SELECT id FROM iam_security_audit ORDER BY recorded_at DESC,id DESC LIMIT 1)
				FROM iam_restore WHERE id=:id
				""").param("id", id).param("checksum", checksum).query(Boolean.class).single();
		if (!accurate) { throw new IllegalStateException("Restore evidence was not stored"); }
		return stored;
	}

	public void invalidateCredentialsAndSessions() {
		// Refresh replay history normally cannot be deleted before expiry. The offline owner discards the entire trust domain atomically.
		this.jdbc.sql("TRUNCATE " + String.join(", ", INVALIDATED_TABLES)).update();
	}

	public void disableSubjectsAndCatalog() {
		this.jdbc.sql("UPDATE iam_user SET status='disabled' WHERE status<>'disabled'").update();
		requireOne(this.jdbc.sql("UPDATE iam_admin_bootstrap SET restore_closed=true,revision=revision+1 WHERE singleton=1").update());
		this.jdbc.sql("UPDATE iam_resource SET status='disabled',version=version+1,updated_at=GREATEST(clock_timestamp(),updated_at) WHERE status<>'disabled'").update();
		this.jdbc.sql("UPDATE iam_resource_role SET status='disabled',version=version+1,updated_at=GREATEST(clock_timestamp(),updated_at) WHERE status<>'disabled'").update();
		this.jdbc.sql("UPDATE iam_user_resource_role_revision SET version=version+1,updated_at=GREATEST(clock_timestamp(),updated_at)").update();
		// The credential trigger permits only disabling this secret; subsequent activation requires a genuinely new secret.
		this.jdbc.sql("UPDATE iam_resource_credential SET status='disabled',version=version+1,updated_at=GREATEST(clock_timestamp(),updated_at) WHERE status='active'").update();
	}

	public List<String> clientIds() { return this.jdbc.sql("SELECT id FROM oauth2_registered_client ORDER BY id").query(String.class).list(); }

	public void eraseClientAccess(String id, String replacementHash) {
		requireOne(this.jdbc.sql("""
				UPDATE oauth2_registered_client SET client_secret=:hash,redirect_uris=:redirect,post_logout_redirect_uris=NULL,
				    scopes='openid',authorization_grant_types='authorization_code' WHERE id=:id AND client_secret<>:hash
				""").param("id", id).param("hash", replacementHash).param("redirect", DISABLED_REDIRECT).update());
		requireOne(this.jdbc.sql("""
				UPDATE iam_client SET status='disabled',version=version+1,updated_at=GREATEST(statement_timestamp(),updated_at),
				    secret_rotated_at=GREATEST(statement_timestamp(),updated_at) WHERE id=:id
				""").param("id", id).update());
		boolean stored = this.jdbc.sql("SELECT client_secret=:hash FROM oauth2_registered_client WHERE id=:id")
				.param("id", id).param("hash", replacementHash).query(Boolean.class).single();
		if (!stored) { throw new IllegalStateException("Restored client credential was not erased"); }
	}

	public void compromiseHistoricalKeys() {
		this.jdbc.sql("""
				UPDATE iam_signing_key SET status='compromised',encrypted_private_key=NULL,protection_key_id=NULL,verification_until=NULL,
				    compromised_at=GREATEST(clock_timestamp(),created_at,retired_at) WHERE status<>'compromised'
				""").update();
		requireOne(this.jdbc.sql("""
				UPDATE iam_signing_key_state SET suspension_key_id=COALESCE(active_key_id,suspension_key_id,initial_key_id),
				    active_key_id=NULL,active_key_created_at=NULL,revision=CASE WHEN initial_key_id IS NULL THEN 0 ELSE revision+1 END
				WHERE singleton=1
				""").update());
	}

	public void activateQuarantine(UUID id, UUID previous) {
		requireOne(this.jdbc.sql("UPDATE iam_restore_state SET current_restore_id=:id WHERE singleton=1 AND current_restore_id IS NOT DISTINCT FROM CAST(:previous AS uuid)")
				.param("id", id).param("previous", previous).update());
		if (!current().map(value -> value.id().equals(id)).orElse(false)) { throw new IllegalStateException("Restore quarantine was not stored"); }
	}

	/** No restored application or other subject is admitted by the release of this one newly established identity. */
	public void verifyReleaseConditions(UUID userId, UUID factorId, UUID signingKeyId) {
		for (String table : INVALIDATED_TABLES) {
			if (!List.of("iam_password", "iam_user_setup", "iam_user_totp", "iam_mfa_recovery_code", "iam_administrator").contains(table)
					&& this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM " + table + ")").query(Boolean.class).single()) {
				throw new IllegalStateException("Restored application or pending credential state remains");
			}
		}
		boolean contained = this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM iam_administrator a JOIN iam_user u ON u.id=a.user_id
				    JOIN iam_password p ON p.user_id=u.id JOIN iam_user_totp t ON t.user_id=u.id
				    WHERE u.id=:user AND u.status='active' AND t.status='active' AND t.factor_id=:factor)
				    AND NOT EXISTS (SELECT 1 FROM iam_administrator WHERE user_id<>:user)
				    AND NOT EXISTS (SELECT 1 FROM iam_user WHERE id<>:user AND status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_password WHERE user_id<>:user)
				    AND NOT EXISTS (SELECT 1 FROM iam_user_totp WHERE user_id<>:user)
				    AND NOT EXISTS (SELECT 1 FROM iam_mfa_recovery_code WHERE user_id<>:user)
				    AND NOT EXISTS (SELECT 1 FROM iam_user_setup WHERE user_id<>:user OR status<>'consumed')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource_role WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_client WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource_credential WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM oauth2_registered_client WHERE redirect_uris IS DISTINCT FROM :redirect
				        OR post_logout_redirect_uris IS NOT NULL OR scopes<>'openid' OR authorization_grant_types<>'authorization_code')
				    AND EXISTS (SELECT 1 FROM iam_signing_key WHERE id=:key AND status='active')
				    AND NOT EXISTS (SELECT 1 FROM iam_signing_key WHERE id<>:key AND status<>'compromised')
				""").param("user", userId).param("factor", factorId).param("key", signingKeyId).param("redirect", DISABLED_REDIRECT).query(Boolean.class).single();
		if (!contained) { throw new IllegalStateException("Restore release conditions are incomplete"); }
	}

	public void verifyQuarantine() {
		for (String table : INVALIDATED_TABLES) {
			if (this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM " + table + ")").query(Boolean.class).single()) {
				throw new IllegalStateException("Restored security state was not invalidated");
			}
		}
		boolean contained = this.jdbc.sql("""
				SELECT NOT EXISTS (SELECT 1 FROM iam_user WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource_role WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_client WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM iam_resource_credential WHERE status<>'disabled')
				    AND NOT EXISTS (SELECT 1 FROM oauth2_registered_client WHERE redirect_uris<>:redirect
				        OR redirect_uris IS NULL OR post_logout_redirect_uris IS NOT NULL OR scopes<>'openid' OR authorization_grant_types<>'authorization_code')
				    AND (SELECT restore_closed FROM iam_admin_bootstrap WHERE singleton=1)
				    AND NOT EXISTS (SELECT 1 FROM iam_signing_key WHERE status<>'compromised' OR encrypted_private_key IS NOT NULL OR protection_key_id IS NOT NULL)
				    AND EXISTS (SELECT 1 FROM iam_signing_key_state s WHERE singleton=1 AND active_key_id IS NULL AND (
				        (initial_key_id IS NULL AND suspension_key_id IS NULL AND NOT EXISTS (SELECT 1 FROM iam_signing_key))
				        OR (initial_key_id IS NOT NULL AND EXISTS (SELECT 1 FROM iam_signing_key k WHERE k.id=s.suspension_key_id AND k.status='compromised'))))
				""").param("redirect", DISABLED_REDIRECT).query(Boolean.class).single();
		if (!contained || isAvailable()) { throw new IllegalStateException("Restore quarantine is incomplete"); }
	}

	private static IdentityRestore restore(ResultSet row) throws SQLException {
		var last = row.getObject("snapshot_last_audit_at", OffsetDateTime.class);
		return new IdentityRestore(row.getObject("id", UUID.class), row.getString("archive_sha256"), row.getString("database_name"),
				row.getObject("quarantined_at", OffsetDateTime.class).toInstant(), row.getLong("snapshot_audit_count"),
				last == null ? null : last.toInstant(), row.getObject("snapshot_last_audit_id", UUID.class));
	}

	private static void requireOne(int changed) { if (changed != 1) { throw new IllegalStateException("Restore containment was not stored"); } }
}
