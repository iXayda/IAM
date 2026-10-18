package com.ixayda.iam.service;

import java.net.InetAddress;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.util.AopTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityPasswordsIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:password-test", "internal:test", UUID.randomUUID());

	@Autowired
	private IdentityPasswords changes;
	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private PlatformTransactionManager transactions;
	@Autowired
	private PostgreSQLContainer postgres;
	@MockitoSpyBean
	private PasswordHasher passwords;
	@MockitoSpyBean
	private SecurityAudits audits;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void rejectsAmbientTransactionsBeforeWritingAuditOrVerificationCounters() throws Exception {
		var user = activeUser("alice");
		String sessionId = session(user.id());
		var context = context();
		new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				assertThatIllegalStateException().isThrownBy(() -> this.changes.change(user.id(), sessionId, 1,
						System.currentTimeMillis(), PASSWORD, NEW_PASSWORD, context))
						.withMessage("Password change requires an independent transaction"));
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
		assertNoPasswordChange(user.id());
	}

	@ParameterizedTest
	@ValueSource(strings = { "wrong-owner", "stale-version", "missing-session", "disabled", "missing-version" })
	void requiresCurrentCredentialsAndAnOwnedActiveSession(String state) throws Exception {
		var alice = activeUser("alice");
		var bob = activeUser("bobby");
		String session = session(state.equals("wrong-owner") ? bob.id() : alice.id());
		if (state.equals("missing-session")) { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
		if (state.equals("disabled")) {
			this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", alice.id()).update();
		}
		long version = state.equals("stale-version") ? 2 : state.equals("missing-version") ? 0 : 1;
		clearInvocations(this.passwords);
		assertThat(this.changes.change(alice.id(), session, version, System.currentTimeMillis(), PASSWORD, NEW_PASSWORD, context()))
				.isEqualTo(IdentityPasswords.Result.INVALID_SESSION);
		verify(this.passwords, never()).matches(any(), any());
		verify(this.passwords, never()).hash(any(), any());
		assertNoPasswordChange(alice.id());
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'password_change_failed'")
				.query(Long.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute" })
	void expiryDuringPasswordHashingCannotChangeThePassword(String deadline) throws Exception {
		var user = activeUser("alice");
		String session = session(user.id());
		long expires = System.currentTimeMillis() + 1000;
		long authenticatedAt = deadline.equals("absolute") ? expires - Duration.ofHours(8).toMillis() : System.currentTimeMillis();
		if (deadline.equals("idle")) {
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry").param("expiry", expires).update();
		}
		doAnswer(call -> {
			Object hash = call.callRealMethod();
			await().atMost(Duration.ofSeconds(3)).until(() -> System.currentTimeMillis() > expires);
			return hash;
		}).when(this.passwords).hash(eq(NEW_PASSWORD), eq("alice"));
		assertThat(this.changes.change(user.id(), session, 1, authenticatedAt, PASSWORD, NEW_PASSWORD, context()))
				.isEqualTo(IdentityPasswords.Result.INVALID_SESSION);
		verify(this.passwords).hash(NEW_PASSWORD, "alice");
		assertNoPasswordChange(user.id());
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute" })
	void expiryDuringSuccessAuditRollsBackThePasswordAndSessionRevocation(String deadline) {
		var user = activeUser("alice");
		String session = session(user.id());
		session(user.id());
		var context = context();
		long expires = System.currentTimeMillis() + 2000;
		long authenticatedAt = deadline.equals("absolute") ? expires - Duration.ofHours(8).toMillis() : System.currentTimeMillis();
		if (deadline.equals("idle")) {
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
					.param("expiry", expires).param("id", session).update();
		}
		SecurityAudits auditTarget = AopTestUtils.getUltimateTargetObject(this.audits);
		doAnswer(call -> {
			Object result = call.callRealMethod();
			await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > expires);
			return result;
		}).when(auditTarget).recordSuccess(eq(Action.PASSWORD_CHANGED), eq(user.id()), any(SecurityAuditContext.class));
		assertThatIllegalStateException().isThrownBy(() -> this.changes.change(user.id(), session, 1, authenticatedAt,
				PASSWORD, NEW_PASSWORD, context)).withMessage("Password session expired during password change");
		verify(auditTarget).recordSuccess(eq(Action.PASSWORD_CHANGED), eq(user.id()), any(SecurityAuditContext.class));
		assertNoPasswordChange(user.id());
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
	}

	@Test
	void upgradingV5PreservesIdentityCredentialsAndAuditAndExpiresOnlyUnversionedAuthenticatedSessions() throws Exception {
		String schema = "password_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "5").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID user = UUID.randomUUID();
				String hash = this.passwords.hash(PASSWORD, "alice");
				previous.sql("INSERT INTO iam_user (id, username, display_name, status) VALUES (:id, 'alice', 'Alice', 'active')")
						.param("id", user).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)")
						.param("id", user).param("hash", hash).update();
				previous.sql("""
						INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
						VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, 'user_created', 'success')
						""").param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", user).update();
				String anonymous = UUID.randomUUID().toString();
				String authenticated = UUID.randomUUID().toString();
				for (String session : List.of(anonymous, authenticated)) {
					previous.sql("""
							INSERT INTO iam_browser_session (primary_id, session_id, creation_time, last_access_time,
							max_inactive_interval, expiry_time, principal_name) VALUES (:id, :id, 1, 1, 1800, 1800001, :principal)
							""").param("id", session).param("principal", session.equals(anonymous) ? null : user.toString(), java.sql.Types.VARCHAR).update();
					previous.sql("INSERT INTO iam_browser_session_attributes VALUES (:id, 'upgrade-marker', :bytes)")
							.param("id", session).param("bytes", new byte[] { 1 }).update();
				}
				var tables = List.of("iam_user", "iam_password", "iam_security_audit");
				var before = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t")
						.query(String.class).single()).toList();
				flyway(schema, "6").migrate();
				var after = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t")
						.query(String.class).single()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(previous.sql("SELECT credential_version FROM iam_password").query(Long.class).single()).isEqualTo(1);
				assertThat(previous.sql("SELECT session_id FROM iam_browser_session").query(String.class).list()).containsExactly(anonymous);
				assertThat(previous.sql("SELECT session_primary_id FROM iam_browser_session_attributes").query(String.class).list()).containsExactly(anonymous);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_password SET credential_version = 0").update())
						.isInstanceOf(DataIntegrityViolationException.class);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'password_changed', outcome = 'failure'").update())
						.isInstanceOf(DataIntegrityViolationException.class);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'password_change_failed', outcome = 'failure', target_user_id = NULL").update())
						.isInstanceOf(DataIntegrityViolationException.class);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityUser activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(user.id()).orElseThrow();
	}

	private String session(UUID userId) {
		String id = UUID.randomUUID().toString();
		long now = System.currentTimeMillis();
		this.jdbc.sql("""
				INSERT INTO iam_browser_session (primary_id, session_id, creation_time, last_access_time,
				max_inactive_interval, expiry_time, principal_name) VALUES (:id, :id, :now, :now, 1800, :expiry, :principal)
				""").param("id", id).param("now", now).param("expiry", now + 1800000).param("principal", userId.toString()).update();
		return id;
	}

	private PasswordAuthenticationContext context() {
		return new PasswordAuthenticationContext("browser:password-change", InetAddress.getLoopbackAddress(), UUID.randomUUID());
	}

	private void assertNoPasswordChange(UUID userId) {
		var credential = this.jdbc.sql("SELECT password_hash, credential_version FROM iam_password WHERE user_id = :id")
				.param("id", userId).query().singleRow();
		assertThat(credential.get("credential_version")).isEqualTo(1L);
		assertThat(this.passwords.matches(PASSWORD, (String) credential.get("password_hash"))).isTrue();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action IN ('password_changed', 'browser_sessions_revoked')")
				.query(Long.class).single()).isZero();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
