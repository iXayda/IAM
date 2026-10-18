package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
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
class IdentityProfilesIntegrationTests {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:profile-test", "internal:test", UUID.randomUUID());

	@Autowired
	private IdentityProfiles profiles;
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
	private SecurityAudits audits;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@ParameterizedTest
	@MethodSource("validDisplayNames")
	void changesOnlyTheDisplayNameAndRecordsTrustedAttribution(String displayName) {
		var user = activeUser();
		String session = session(user.id());
		var before = this.jdbc.sql("SELECT (to_jsonb(u) - 'display_name')::text FROM iam_user u").query(String.class).single();
		var credential = this.jdbc.sql("SELECT row_to_json(p)::text FROM iam_password p").query(String.class).single();
		UUID correlation = UUID.randomUUID();
		assertThat(this.profiles.updateDisplayName(user.id(), session, 1, System.currentTimeMillis(), displayName, correlation))
				.isEqualTo(IdentityProfiles.Result.UPDATED);
		assertThat(this.users.findById(user.id()).orElseThrow().displayName())
				.isEqualTo(java.text.Normalizer.normalize(displayName, java.text.Normalizer.Form.NFC));
		assertThat(this.jdbc.sql("SELECT (to_jsonb(u) - 'display_name')::text FROM iam_user u").query(String.class).single()).isEqualTo(before);
		assertThat(this.jdbc.sql("SELECT row_to_json(p)::text FROM iam_password p").query(String.class).single()).isEqualTo(credential);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(1);
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'user_profile_updated'").query().singleRow();
		assertThat(event.get("actor")).isEqualTo("user:" + user.id());
		assertThat(event.get("source")).isEqualTo("browser:profile-change");
		assertThat(event.get("correlation_id")).isEqualTo(correlation);
		assertThat(event.get("target_user_id")).isEqualTo(user.id());
		assertThat(event.get("outcome")).isEqualTo("success");
		assertThat(event.keySet()).doesNotContain("display_name", "password_hash");
	}

	static Stream<String> validDisplayNames() {
		return Stream.of("名", "😀".repeat(128), " Cafe\u0301 用户 ");
	}

	@ParameterizedTest
	@NullAndEmptySource
	@MethodSource("invalidDisplayNames")
	void rejectsInvalidNamesWithoutUpdatingTheUserOrRecordingSuccess(String displayName) {
		var user = activeUser();
		String session = session(user.id());
		assertThat(update(user.id(), session, displayName)).isEqualTo(IdentityProfiles.Result.INVALID_DISPLAY_NAME);
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(profileEvents()).isZero();
	}

	static Stream<String> invalidDisplayNames() {
		return Stream.of(" \u00a0\u3000", "Alice\n", "bad\ud800", "bad\udc00", "😀".repeat(129), "a".repeat(65_537));
	}

	@Test
	void repeatingAnEquivalentNormalizedNameDoesNotCreateAnotherEvent() {
		var user = activeUser();
		String session = session(user.id());
		assertThat(update(user.id(), session, "Alice")).isEqualTo(IdentityProfiles.Result.UNCHANGED);
		assertThat(profileEvents()).isZero();
		assertThat(update(user.id(), session, " Café ")).isEqualTo(IdentityProfiles.Result.UPDATED);
		assertThat(update(user.id(), session, " Cafe\u0301 ")).isEqualTo(IdentityProfiles.Result.UNCHANGED);
		assertThat(profileEvents()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "owner", "missing", "idle", "absolute", "future", "version", "disabled", "pending" })
	void requiresCurrentCredentialsAndAnOwnedUnexpiredSession(String state) {
		var user = activeUser();
		String session = session(state.equals("owner") ? UUID.randomUUID() : user.id());
		if (state.equals("missing")) { this.jdbc.sql("DELETE FROM iam_browser_session").update(); }
		if (state.equals("idle")) { this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = 1").update(); }
		if (state.equals("disabled") || state.equals("pending")) {
			this.jdbc.sql("UPDATE iam_user SET status = :status").param("status", state).update();
		}
		long now = System.currentTimeMillis();
		long authenticatedAt = state.equals("absolute") ? now - Duration.ofHours(8).toMillis()
				: state.equals("future") ? now + 60_000 : now;
		assertThat(this.profiles.updateDisplayName(user.id(), session, state.equals("version") ? 2 : 1,
				authenticatedAt, "Changed", UUID.randomUUID())).isEqualTo(IdentityProfiles.Result.INVALID_SESSION);
		assertThat(this.users.findById(user.id()).orElseThrow().displayName()).isEqualTo("Alice");
		assertThat(profileEvents()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute" })
	void expiryDuringSuccessAuditRollsBackTheProfileAndItsAudit(String deadline) {
		var user = activeUser();
		String session = session(user.id());
		long expires = System.currentTimeMillis() + 1500;
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
		}).when(auditTarget).recordSuccess(eq(Action.USER_PROFILE_UPDATED), eq(user.id()), any(SecurityAuditContext.class));
		assertThatIllegalStateException().isThrownBy(() -> this.profiles.updateDisplayName(user.id(), session, 1,
				authenticatedAt, "Changed", UUID.randomUUID())).withMessage("Password session expired during profile update");
		verify(auditTarget).recordSuccess(eq(Action.USER_PROFILE_UPDATED), eq(user.id()), any(SecurityAuditContext.class));
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(profileEvents()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void anOuterRollbackRestoresBothTheProfileAndItsAudit() {
		var user = activeUser();
		String session = session(user.id());
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			assertThat(update(user.id(), session, "Changed")).isEqualTo(IdentityProfiles.Result.UPDATED);
			assertThat(profileEvents()).isEqualTo(1);
			status.setRollbackOnly();
		});
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(profileEvents()).isZero();
	}

	@Test
	void concurrentEquivalentUpdatesProduceOnlyOneChangeAndEvent() throws Exception {
		var user = activeUser();
		String firstSession = session(user.id());
		String secondSession = session(user.id());
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> { assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return update(user.id(), firstSession, "Café"); });
			var second = executor.submit(() -> { assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return update(user.id(), secondSession, "Cafe\u0301"); });
			start.countDown();
			assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
					.containsExactlyInAnyOrder(IdentityProfiles.Result.UPDATED, IdentityProfiles.Result.UNCHANGED);
		}
		assertThat(this.users.findById(user.id()).orElseThrow().displayName()).isEqualTo("Café");
		assertThat(profileEvents()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-idle", "user-absolute", "session-idle", "session-absolute" })
	void rechecksExpiryAfterWaitingForEitherLock(String lockAndDeadline) throws Exception {
		var user = activeUser();
		String session = session(user.id());
		long deadline = System.currentTimeMillis() + 1500;
		long authenticatedAt = lockAndDeadline.endsWith("absolute") ? deadline - Duration.ofHours(8).toMillis() : System.currentTimeMillis();
		if (lockAndDeadline.endsWith("idle")) {
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry").param("expiry", deadline).update();
		}
		try (var blocker = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try {
				int pid;
				try (var statement = blocker.createStatement(); var result = statement.executeQuery("SELECT pg_backend_pid()")) {
					result.next(); pid = result.getInt(1);
				}
				try (var statement = blocker.prepareStatement(lockAndDeadline.startsWith("user")
						? "SELECT id FROM iam_user WHERE id = ? FOR UPDATE"
						: "SELECT session_id FROM iam_browser_session WHERE session_id = ? FOR UPDATE")) {
					statement.setObject(1, lockAndDeadline.startsWith("user") ? user.id() : session);
					statement.executeQuery().close();
				}
				var waiting = executor.submit(() -> this.profiles.updateDisplayName(user.id(), session, 1, authenticatedAt, "Changed", UUID.randomUUID()));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql(
						"SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
						.param("pid", pid).query(Boolean.class).single());
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
				blocker.commit();
				assertThat(waiting.get(10, TimeUnit.SECONDS)).isEqualTo(IdentityProfiles.Result.INVALID_SESSION);
			}
			finally { blocker.rollback(); }
		}
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(profileEvents()).isZero();
	}

	@Test
	void upgradingV7PreservesExistingDataAndExtendsOnlyTheAuditContract() throws Exception {
		var user = activeUser();
		String session = session(user.id());
		this.jdbc.sql("INSERT INTO iam_browser_session_attributes VALUES (:id, 'upgrade-marker', :bytes)")
				.param("id", session).param("bytes", new byte[] { 1, 2 }).update();
		String schema = "profile_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "7").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID userId = user.id();
				var tables = List.of("iam_user", "iam_password", "iam_user_setup", "iam_browser_session", "iam_browser_session_attributes");
				for (String table : tables) {
					previous.sql("INSERT INTO " + table + " SELECT * FROM public." + table).update();
				}
				for (Action action : EnumSet.range(Action.USER_CREATED, Action.PASSWORD_RECOVERY_FAILED)) {
					previous.sql("""
							INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
							VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, :action, :outcome)
							""").param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", userId)
							.param("action", action.name().toLowerCase(Locale.ROOT)).param("outcome", action.isFailure() ? "failure" : "success").update();
				}
				var before = previous.sql("SELECT row_to_json(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list();
				var businessBefore = tables.stream().map(table -> previous.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1")
						.query(String.class).list()).toList();
				flyway(schema, "8").migrate();
				assertThat(previous.sql("SELECT row_to_json(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list()).isEqualTo(before);
				assertThat(tables.stream().map(table -> previous.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1")
						.query(String.class).list()).toList()).isEqualTo(businessBefore);
				previous.sql("""
						INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
						VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, 'user_profile_updated', 'success')
						""").param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", userId).update();
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET outcome = 'failure' WHERE action = 'user_profile_updated'").update())
						.isInstanceOf(DataIntegrityViolationException.class);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET target_user_id = NULL WHERE action = 'user_profile_updated'").update())
						.isInstanceOf(DataIntegrityViolationException.class);
				assertThatThrownBy(() -> previous.sql("UPDATE iam_security_audit SET action = 'unknown_action'").update())
						.isInstanceOf(DataIntegrityViolationException.class);
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityUser activeUser() {
		var user = this.users.create("alice", "Alice", SYSTEM);
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

	private IdentityProfiles.Result update(UUID userId, String sessionId, String displayName) {
		return this.profiles.updateDisplayName(userId, sessionId, 1, System.currentTimeMillis(), displayName, UUID.randomUUID());
	}

	private long profileEvents() {
		return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'user_profile_updated'").query(Long.class).single();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
