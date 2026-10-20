package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityAuthorizationSession;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthorizationSessionsIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final String PASSWORD = "Ceramic orchard quartz river 87";
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:application-sessions-test", "internal:application-sessions", UUID.randomUUID());
	@Autowired private IdentityAuthorizationSessions applications;
	@Autowired private IdentityApplicationRoles applicationRoles;
	@Autowired private IdentityProtocolClients protocol;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUserRoles bindings;
	@Autowired private IdentitySigningKeys keys;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	private SessionRepository<Session> store;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;
	private IdentityProtocolClients.Snapshot client;
	private String sessionId;
	private long authenticatedAt;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.signing.key-file", KEY_FILE::toString); }

	@BeforeEach
	@SuppressWarnings("unchecked")
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_browser_session,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.keys.initialize();
		this.userId = activeUser("alice");
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var configuration = new IdentityClientConfiguration("Orders", this.resourceId, List.of("https://orders.example/callback"), Set.of("openid", "profile"), Set.of(this.roleId));
		this.client = this.protocol.findActiveById(this.clients.create(configuration, AUDIT).client().id().toString()).orElseThrow();
		var official = new JdbcIndexedSessionRepository(this.template, new TransactionTemplate(this.transactions));
		official.setTableName("iam_browser_session"); official.setDefaultMaxInactiveInterval(Duration.ofMinutes(30));
		// JdbcSession is package-private; use the official repository's public Session interface.
		this.store = (SessionRepository<Session>) (SessionRepository<?>) official;
		this.authenticatedAt = System.currentTimeMillis() - 1000;
		var session = this.store.createSession();
		session.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT, new SecurityContextImpl(
				UsernamePasswordAuthenticationToken.authenticated(this.userId, null, List.of(new SimpleGrantedAuthority("IAM_ADMINISTRATOR")))));
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt);
		session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1L);
		this.store.save(session); this.sessionId = session.getId();
	}

	@AfterEach
	void removeReferences() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user_role,iam_user_resource_role_revision,iam_browser_session CASCADE").update();
	}

	@Test
	void projectionUsesOfficialStoredOwnershipAndPrimitiveFactsWithoutCopyingBrowserAuthentication() {
		var before = snapshot();
		var projected = project().orElseThrow();
		UUID primaryId = UUID.fromString(this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).query(String.class).single());
		assertThat(projected.browserSessionId()).isEqualTo(primaryId).isNotEqualTo(UUID.fromString(this.sessionId));
		assertThat(projected.authenticatedAt()).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt));
		assertThat(projected.absoluteExpiresAt()).isEqualTo(projected.authenticatedAt().plusSeconds(28_800));
		assertThat(projected.idleExpiresAt()).isEqualTo(Instant.ofEpochMilli(this.jdbc.sql("SELECT expiry_time FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).query(Long.class).single()));
		assertThat(projected.expiresAt()).isEqualTo(projected.idleExpiresAt());
		assertThat(projected.access().userId()).isEqualTo(this.userId);
		assertThat(projected.access().roles()).extracting(role -> role.code()).containsExactly("reader");
		assertThat(projected.toString()).doesNotContain(this.sessionId, this.userId.toString(), "reader", "IAM_ADMINISTRATOR");
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void anInternalSessionIdentitySurvivesOfficialSessionRotationWhileTheOldCookieStopsWorking() {
		var original = project().orElseThrow();
		String oldId = this.sessionId;
		var session = this.store.findById(oldId); assertThat(session).isNotNull();
		session.changeSessionId(); this.store.save(session); this.sessionId = session.getId();
		assertThat(project(this.userId, oldId, this.authenticatedAt, 1)).isEmpty();
		var rotated = project().orElseThrow();
		assertThat(rotated.browserSessionId()).isEqualTo(original.browserSessionId());
		assertThat(rotated.authenticatedAt()).isEqualTo(original.authenticatedAt());
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "foreign", "null", "noncanonical", "wrong-time", "wrong-version", "future-time", "absolute-expired", "idle-expired", "missing-time", "missing-version", "wrong-time-type", "wrong-version-type", "corrupt-time", "corrupt-version" })
	void missingForeignExpiredAndMismatchedPersistedSessionFactsNeverAuthorize(String invalid) {
		String id = this.sessionId; UUID subject = this.userId; long time = this.authenticatedAt;
		switch (invalid) {
			case "missing" -> id = UUID.randomUUID().toString();
			case "foreign" -> subject = activeUser("bobby");
			case "null" -> id = null;
			case "noncanonical" -> id = "1-1-1-1-1";
			case "wrong-time" -> time--;
			case "wrong-version" -> attribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 2L);
			case "future-time" -> { time = System.currentTimeMillis() + 60_000; attribute(IdentityBrowserSessions.AUTHENTICATED_AT, time); }
			case "absolute-expired" -> { time = System.currentTimeMillis() - 28_800_001; attribute(IdentityBrowserSessions.AUTHENTICATED_AT, time); }
			case "idle-expired" -> this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", id).update();
			case "missing-time" -> removeAttribute(IdentityBrowserSessions.AUTHENTICATED_AT);
			case "missing-version" -> removeAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION);
			case "wrong-time-type" -> attribute(IdentityBrowserSessions.AUTHENTICATED_AT, Long.toString(time));
			case "wrong-version-type" -> attribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1);
			case "corrupt-time" -> rawAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, new byte[] {1, 2, 3});
			default -> rawAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, new byte[] {1, 2, 3});
		}
		var before = snapshot();
		assertThat(project(subject, id, time, 1)).isEmpty();
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void browserAbsoluteDeadlineWinsEvenWhenTheStoredIdleDeadlineIsLater() {
		this.authenticatedAt = System.currentTimeMillis() - Duration.ofHours(7).toMillis() - Duration.ofMinutes(50).toMillis();
		attribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt);
		var context = project().orElseThrow();
		assertThat(context.absoluteExpiresAt()).isBefore(context.idleExpiresAt());
		assertThat(context.expiresAt()).isEqualTo(context.absoluteExpiresAt());
	}

	@ParameterizedTest
	@ValueSource(strings = { "credential", "disabled", "pending", "client", "resource" })
	void aPersistedBrowserSessionCannotBypassCurrentSubjectOrCatalogState(String invalid) {
		switch (invalid) {
			case "credential" -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> { this.users.lockById(this.userId); this.users.invalidateAuthentications(this.userId, 1); });
			case "disabled" -> this.states.disable(this.userId, AUDIT);
			case "pending" -> this.userId = this.users.create("pending", "Pending", AUDIT).id();
			case "client" -> this.clients.setEnabled(this.client.client().id(), 1, false, AUDIT);
			default -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		}
		assertThat(project()).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "ownership", "time", "credential", "expiry", "delete" })
	void sessionLockWaitsAreFollowedByFreshOwnershipFactAndDeadlineChecks(String change) throws Exception {
		UUID other = activeUser("bobby");
		var changed = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE session_id=:id FOR UPDATE").param("id", this.sessionId).query(String.class).single();
					switch (change) {
						case "ownership" -> this.jdbc.sql("UPDATE iam_browser_session SET principal_name=:principal WHERE session_id=:id").param("principal", other.toString()).param("id", this.sessionId).update();
						case "time" -> attribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt - 1);
						case "credential" -> attribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 2L);
						case "expiry" -> this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", this.sessionId).update();
						default -> this.jdbc.sql("DELETE FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).update();
					}
					changed.countDown(); awaitLatch(release);
				}));
				awaitLatch(changed);
				var issuer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-session-waiting-issuer"); return this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client);
				}));
				awaitLockWait("iam-session-waiting-issuer");
				release.countDown(); writer.get(10, TimeUnit.SECONDS);
				assertThat(issuer.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute" })
	void aDeadlineThatPassesWhileWaitingCannotBeExtendedByTheRequest(String deadline) throws Exception {
		long expiry = System.currentTimeMillis() + 700;
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		if (deadline.equals("idle")) {
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", expiry).param("id", this.sessionId).update();
		}
		else {
			this.authenticatedAt = expiry - Duration.ofHours(8).toMillis(); attribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt);
		}
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE session_id=:id FOR UPDATE").param("id", this.sessionId).query(String.class).single();
					locked.countDown(); awaitLatch(release);
				}));
				awaitLatch(locked);
				var issuer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-session-deadline-issuer"); return this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client);
				}));
				awaitLockWait("iam-session-deadline-issuer");
				await().atMost(Duration.ofSeconds(3)).until(() -> System.currentTimeMillis() > expiry);
				release.countDown(); writer.get(10, TimeUnit.SECONDS);
				assertThat(issuer.get(10, TimeUnit.SECONDS)).isEmpty();
				if (deadline.equals("idle")) { assertThat(this.jdbc.sql("SELECT expiry_time FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).query(Long.class).single()).isEqualTo(expiry); }
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void browserProjectionAcquiresTheExclusiveSubjectLockBeforeASessionSaveAndRetainsItThroughCommit() throws Exception {
		var locked = new CountDownLatch(1); var upgrade = new CountDownLatch(1); var upgraded = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var first = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					assertThat(this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client)).isPresent();
					locked.countDown(); awaitLatch(upgrade);
					this.users.lockById(this.userId);
					var session = this.store.findById(this.sessionId); session.setLastAccessedTime(Instant.now()); this.store.save(session);
					upgraded.countDown(); awaitLatch(release);
				}));
				awaitLatch(locked);
				var second = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-session-parallel-issuer"); return this.applicationRoles.projectForIssuance(this.userId, 1, this.client);
				}));
				awaitLockWait("iam-session-parallel-issuer"); upgrade.countDown(); awaitLatch(upgraded);
				release.countDown(); first.get(10, TimeUnit.SECONDS);
				assertThat(second.get(10, TimeUnit.SECONDS)).isPresent();
			}
			finally { upgrade.countDown(); release.countDown(); }
		}
	}

	@Test
	void projectionRequiresAnExistingWritableReadCommittedTransactionAndDoesNotWriteAfterRollback() {
		assertThatThrownBy(() -> this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client)).isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		var readOnly = new TransactionTemplate(this.transactions); readOnly.setReadOnly(true);
		assertThatIllegalStateException().isThrownBy(() -> readOnly.execute(tx -> this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client)));
		var repeatable = new TransactionTemplate(this.transactions); repeatable.setIsolationLevel(org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ);
		assertThatIllegalStateException().isThrownBy(() -> repeatable.execute(tx -> this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client)));
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThat(this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client)).isPresent(); tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void aSessionAttributeReadFailureCannotBecomeAMissingOrSuccessfulContext() {
		String reader = "session_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + reader).update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + reader).update();
			this.jdbc.sql("GRANT SELECT ON ALL TABLES IN SCHEMA public TO " + reader).update();
			this.jdbc.sql("GRANT UPDATE ON iam_signing_key_state,iam_user,iam_resource,iam_resource_role,iam_client,oauth2_registered_client,iam_browser_session TO " + reader).update();
			this.jdbc.sql("REVOKE SELECT ON iam_browser_session_attributes FROM " + reader).update();
			var before = snapshot();
			assertThatThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + reader).update();
				return this.applications.projectForIssuance(this.userId, this.sessionId, this.authenticatedAt, 1, this.client);
			})).isInstanceOf(org.springframework.dao.DataAccessException.class).rootCause()
					.isInstanceOfSatisfying(org.postgresql.util.PSQLException.class, ex -> {
						assertThat(ex.getSQLState()).isEqualTo("42501"); assertThat(ex.getMessage()).contains("iam_browser_session_attributes");
					});
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { this.jdbc.sql("DROP OWNED BY " + reader).update(); this.jdbc.sql("DROP ROLE " + reader).update(); }
	}

	private Optional<IdentityAuthorizationSession> project() { return project(this.userId, this.sessionId, this.authenticatedAt, 1); }
	private Optional<IdentityAuthorizationSession> project(UUID user, String id, long time, long credential) {
		return new TransactionTemplate(this.transactions).execute(tx -> this.applications.projectForIssuance(user, id, time, credential, this.client));
	}
	private UUID activeUser(String name) {
		var user = this.users.create(name, name, AUDIT); var setup = this.setups.issue(user.id(), AUDIT);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:application-sessions", UUID.randomUUID()); return user.id();
	}
	private void attribute(String name, Object value) { rawAttribute(name, SerializationUtils.serialize(value)); }
	private void rawAttribute(String name, byte[] value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes=:bytes WHERE session_primary_id=(SELECT primary_id FROM iam_browser_session WHERE session_id=:id) AND attribute_name=:name")
				.param("bytes", value).param("id", this.sessionId).param("name", name).update();
	}
	private void removeAttribute(String name) {
		this.jdbc.sql("DELETE FROM iam_browser_session_attributes WHERE session_primary_id=(SELECT primary_id FROM iam_browser_session WHERE session_id=:id) AND attribute_name=:name")
				.param("id", this.sessionId).param("name", name).update();
	}
	private List<String> snapshot() {
		return List.of("iam_user", "iam_password", "iam_client", "iam_browser_session", "iam_browser_session_attributes", "iam_security_audit").stream()
				.map(table -> table + this.jdbc.sql("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM " + table + " t").query(String.class).single()).toList();
	}
	private void applicationName(String name) { this.jdbc.sql("SELECT set_config('application_name',:name,true)").param("name", name).query(String.class).single(); }
	private void awaitLockWait(String name) {
		await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=:name AND wait_event_type='Lock')")
				.param("name", name).query(Boolean.class).single());
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent workflow did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-application-session-signing-", ".key"); byte[] bytes = new byte[32];
			new SecureRandom().nextBytes(bytes); Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
