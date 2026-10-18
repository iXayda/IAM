package com.ixayda.iam.security;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import javax.sql.DataSource;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.service.IdentityAuthentications;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.SecurityAudits;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@Import(PostgreSqlTestConfiguration.class)
class IdentityPasswordAuthenticationIntegrationTests {

	private static final String PASSWORD = " Seven amber lanterns by the Café ";

	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:authentication-test", "internal:test", UUID.randomUUID());

	@Autowired
	private AuthenticationManager manager;

	@Autowired
	private IdentityUsers users;

	@Autowired
	private IdentityAuthentications authentications;

	@Autowired
	private IdentityUserSetups setups;

	@Autowired
	private SecurityAudits audits;

	@Autowired
	private JdbcClient jdbc;

	@Autowired
	private PlatformTransactionManager transactions;

	@Autowired
	private DataSource dataSource;

	@Autowired
	private PostgreSQLContainer postgres;

	@MockitoSpyBean
	private PasswordHasher passwords;

	@BeforeEach
	void removeTestData() {
		for (String table : List.of("iam_password_authentication_limit", "iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
		clearInvocations(this.passwords);
	}

	@Test
	void authenticatesAnActiveUserWithStableIdentityAndNoCredentialsOrAuthorities() {
		IdentityUser user = activeUser("alice");
		var context = context(1);
		var request = request("ALICE", " Seven amber lanterns by the Cafe\u0301 ", context);
		Authentication result = this.manager.authenticate(request);
		assertThat(result.isAuthenticated()).isTrue();
		assertThat(result.getPrincipal()).isEqualTo(user.id());
		assertThat(result.getCredentials()).isNull();
		assertThat(result.getAuthorities()).isEmpty();
		assertThat(request.getCredentials()).isNull();
		assertThat(this.manager).isInstanceOf(ProviderManager.class);
		assertThat(((ProviderManager) this.manager).isEraseCredentialsAfterAuthentication()).isTrue();
		var event = authEvents().getFirst();
		assertThat(event.get("action")).isEqualTo("password_authenticated");
		assertThat(event.get("outcome")).isEqualTo("success");
		assertThat(event.get("actor")).isEqualTo("user:" + user.id());
		assertThat(event.get("target_user_id")).isEqualTo(user.id());
		assertThat(event.get("source")).isEqualTo(context.source());
		assertThat(event.get("correlation_id")).isEqualTo(context.correlationId());
		assertThat(result.toString()).doesNotContain(PASSWORD, storedHash(user.id()));
	}

	@Test
	void wrongPasswordAndUnknownUserHaveTheSameDenialAndPersistFailureAudit() {
		IdentityUser user = activeUser("alice");
		for (String name : List.of("alice", "unknown")) {
			var request = request(name, "wrong but long enough password", context(1));
			assertThatThrownBy(() -> this.manager.authenticate(request)).isExactlyInstanceOf(BadCredentialsException.class)
					.hasMessage("Invalid credentials");
			assertThat(request.getCredentials()).isNull();
		}
		var events = authEvents();
		assertThat(events).hasSize(2).allSatisfy(event -> {
			assertThat(event.get("action")).isEqualTo("password_auth_failed");
			assertThat(event.get("outcome")).isEqualTo("failure");
			assertThat(event.get("actor")).isEqualTo("anonymous");
		});
		assertThat(events.getFirst().get("target_user_id")).isEqualTo(user.id());
		assertThat(events.getLast().get("target_user_id")).isNull();
		assertThat(sourceFailures()).isEqualTo(2);
	}

	@Test
	void unknownUserAndMissingPasswordStillPerformPlaceholderVerification() {
		this.users.create("pending-user", "Pending", SYSTEM);
		clearInvocations(this.passwords);
		deny("unknown", PASSWORD, context(1));
		deny("pending-user", PASSWORD, context(2));
		verify(this.passwords, times(2)).matches(eq(PASSWORD), startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending", "disabled", "active-without-password" })
	void refusesNonActiveAccountsAndAccountsWithoutPassword(String state) {
		IdentityUser user = state.equals("active-without-password") ? this.users.create("alice", "Alice", SYSTEM) : activeUser("alice");
		this.jdbc.sql("UPDATE iam_user SET status = :state WHERE id = :id")
				.param("state", state.equals("active-without-password") ? "active" : state).param("id", user.id()).update();
		deny("alice", PASSWORD, context(1));
		assertThat(authEvents()).hasSize(1);
		assertThat(sourceFailures()).isEqualTo(1);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "ab", " alice", "alice ", "álîce", "alice@example.com", "alice'--", "bad\nname" })
	void malformedUsernamesHaveTheSameFailureWithoutLeakingInput(String username) {
		deny(username, PASSWORD, context(1));
		assertThat(authEvents()).hasSize(1);
		assertThat(authEvents().getFirst().get("target_user_id")).isNull();
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "wrong", " Seven amber lanterns by the CAFÉ ", "Seven amber lanterns by the Café", "bad\ud800" })
	void wrongOrMalformedPasswordsAreNotTrimmedOrCaseFolded(String password) {
		activeUser("alice");
		deny("alice", password, context(1));
		assertThat(sourceFailures()).isEqualTo(1);
	}

	@Test
	void oversizedInputsAreRejectedAsOrdinaryDenials() {
		deny("a".repeat(65_537), PASSWORD, context(1));
		activeUser("alice");
		deny("alice", "p".repeat(65_537), context(1));
		assertThat(authEvents()).hasSize(2);
	}

	@Test
	void verificationDoesNotReapplyCurrentPasswordSettingRules() {
		IdentityUser user = activeUser("alice");
		String legacyHash = new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2).encode("short");
		this.jdbc.sql("UPDATE iam_password SET password_hash = :hash WHERE user_id = :id").param("hash", legacyHash).param("id", user.id()).update();
		assertThat(authenticate("alice", "short", context(1)).getPrincipal()).isEqualTo(user.id());
	}

	@Test
	void accountLimitSharesCaseVariantsAndDifferentSourcesAndDoesNotExtendOnDenial() {
		activeUser("alice");
		for (int i = 0; i < 10; i++) { deny(i % 2 == 0 ? "ALICE" : "alice", "wrong", context(i + 1)); }
		String before = accountWindow();
		clearInvocations(this.passwords);
		deny("alice", PASSWORD, context(40));
		deny("ALICE", PASSWORD, context(41));
		verify(this.passwords, never()).matches(any(), any());
		assertThat(accountFailures()).isEqualTo(10);
		assertThat(accountWindow()).isEqualTo(before);
		assertThat(authEvents()).filteredOn(event -> event.get("action").equals("password_auth_failed")).hasSize(10);
		assertThat(authEvents()).filteredOn(event -> event.get("action").equals("password_auth_throttled")).hasSize(2);
		assertThat(sourceFailures()).isEqualTo(10);
	}

	@Test
	void sourceLimitAppliesAcrossAccountsAndDoesNotAllowCorrectPasswordsThrough() {
		activeUser("alice");
		for (int i = 0; i < 50; i++) { deny("unknown-" + i, PASSWORD, context(1)); }
		deny("alice", PASSWORD, context(1));
		assertThat(sourceFailures()).isEqualTo(50);
		assertThat(authEvents().getLast().get("action")).isEqualTo("password_auth_throttled");
		assertThat(authenticate("alice", PASSWORD, context(2)).isAuthenticated()).isTrue();
	}

	@Test
	void sourceThrottlingDoesNotCreateOrResetAccountBuckets() {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update();
		this.jdbc.sql("UPDATE iam_password_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '15 minutes' WHERE dimension = 'account'").update();
		String snapshot = "SELECT row_to_json(t)::text FROM iam_password_authentication_limit t ORDER BY dimension, subject_key";
		var before = this.jdbc.sql(snapshot).query(String.class).list();
		clearInvocations(this.passwords);
		for (int i = 0; i < 20; i++) {
			var request = request("blocked-unknown-" + i, PASSWORD, context(1));
			assertThatThrownBy(() -> this.manager.authenticate(request)).isExactlyInstanceOf(BadCredentialsException.class)
					.hasMessage("Invalid credentials");
			assertThat(request.getCredentials()).isNull();
		}
		deny("alice", PASSWORD, context(1));
		assertThat(this.jdbc.sql(snapshot).query(String.class).list()).isEqualTo(before);
		verify(this.passwords, never()).matches(any(), any());
		assertThat(authEvents()).hasSize(22);
		assertThat(authEvents()).filteredOn(event -> event.get("action").equals("password_auth_throttled"))
				.hasSize(21).allSatisfy(event -> {
					assertThat(event.get("target_user_id")).isNull();
					assertThat(event.get("actor")).isEqualTo("anonymous");
					assertThat(event.get("outcome")).isEqualTo("failure");
				});
	}

	@Test
	void sourceThrottlingDoesNotWaitForTheAccountLock() throws Exception {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update();
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT subject_key FROM iam_password_authentication_limit WHERE dimension = 'account' FOR UPDATE");
					var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
			var request = request("alice", PASSWORD, context(1));
			var result = executor.submit(() -> this.manager.authenticate(request));
			try {
				assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(BadCredentialsException.class);
				assertThat(request.getCredentials()).isNull();
			}
			finally { blocker.rollback(); }
		}
		assertThat(sourceFailures()).isEqualTo(50);
		assertThat(accountFailures()).isEqualTo(1);
		assertThat(authEvents()).hasSize(2);
		assertThat(authEvents().getLast().get("action")).isEqualTo("password_auth_throttled");
	}

	@Test
	void successfulAuthenticationClearsOnlyTheAccountFailureCount() {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		deny("alice", "wrong", context(1));
		authenticate("alice", PASSWORD, context(1));
		assertThat(accountFailures()).isZero();
		assertThat(sourceFailures()).isEqualTo(2);
	}

	@Test
	void expiredWindowsResetAndAllowTheNextAttempt() {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		this.jdbc.sql("""
				UPDATE iam_password_authentication_limit SET failures = CASE dimension WHEN 'account' THEN 10 ELSE 50 END,
				    window_started_at = clock_timestamp() - INTERVAL '15 minutes'
				""").update();
		assertThat(authenticate("alice", PASSWORD, context(1)).isAuthenticated()).isTrue();
		assertThat(sourceFailures()).isZero();
		assertThat(accountFailures()).isZero();
	}

	@Test
	void sourceExpiryDoesNotClearAnAccountThatIsStillThrottled() {
		activeUser("alice");
		for (int i = 0; i < 10; i++) { deny("alice", "wrong", context(1)); }
		this.jdbc.sql("UPDATE iam_password_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '5 minutes' WHERE dimension = 'source'").update();
		deny("alice", PASSWORD, context(1));
		assertThat(sourceFailures()).isZero();
		assertThat(accountFailures()).isEqualTo(10);
	}

	@Test
	void mappedIpv6AndIpv4PeersShareTheSameSourceLimit() throws Exception {
		byte[] mapped = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, (byte) 192, 0, 2, 1 };
		var ipv6 = new PasswordAuthenticationContext("internal:test", Inet6Address.getByAddress(null, mapped, -1), UUID.randomUUID());
		deny("unknown-one", PASSWORD, context(1));
		deny("unknown-two", PASSWORD, ipv6);
		assertThat(sourceFailures()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit WHERE dimension = 'source'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void ipv6RepresentationsShareTheSameSourceLimit() throws Exception {
		deny("unknown-one", PASSWORD, new PasswordAuthenticationContext("internal:test", InetAddress.getByName("2001:db8::1"), UUID.randomUUID()));
		deny("unknown-two", PASSWORD, new PasswordAuthenticationContext("internal:test", InetAddress.getByName("2001:db8:0:0:0:0:0:1"), UUID.randomUUID()));
		assertThat(sourceFailures()).isEqualTo(2);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit WHERE dimension = 'source'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void missingTrustedContextErasesCredentialsAndWritesNothing() {
		var request = UsernamePasswordAuthenticationToken.unauthenticated("alice", PASSWORD);
		assertThatThrownBy(() -> this.manager.authenticate(request)).isInstanceOf(AuthenticationServiceException.class)
				.hasMessage("Trusted authentication context is required");
		assertThat(request.getCredentials()).isNull();
		assertThat(authEvents()).isEmpty();
		assertThat(count("iam_password_authentication_limit")).isZero();
	}

	@Test
	void ambientTransactionsAreRejectedBeforeEvaluationAndCredentialsAreErased() {
		var request = request("alice", PASSWORD, context(1));
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			assertThatThrownBy(() -> this.manager.authenticate(request)).isInstanceOf(AuthenticationServiceException.class)
					.hasMessage("Password authentication requires an independent transaction");
		});
		assertThat(request.getCredentials()).isNull();
		assertThat(authEvents()).isEmpty();
		assertThat(count("iam_password_authentication_limit")).isZero();
	}

	@Test
	void internalDecisionsAlsoRejectAmbientTransactionsBeforeAnyWrite() {
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			assertThatIllegalStateException().isThrownBy(() -> this.authentications.authenticate("alice", PASSWORD, context(1)))
					.withMessage("Password authentication requires an independent transaction");
		});
		assertThat(authEvents()).isEmpty();
		assertThat(count("iam_password_authentication_limit")).isZero();
	}

	@Test
	void aLaterUnrelatedRollbackCannotEraseAnAlreadyCommittedFailure() {
		deny("unknown", PASSWORD, context(1));
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.users.create("another-user", "Another User", SYSTEM);
			status.setRollbackOnly();
		});
		assertThat(this.users.findByUsername("another-user")).isEmpty();
		assertThat(authEvents()).hasSize(1);
		assertThat(sourceFailures()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "success", "failure", "throttled", "source-throttled" })
	void requiredAuditFailureRejectsAuthenticationAndRollsBackCounters(String mode) {
		activeUser("alice");
		int previous = mode.equals("throttled") ? 10 : 1;
		for (int i = 0; i < previous; i++) { deny("alice", "wrong", context(1)); }
		if (mode.equals("source-throttled")) {
			this.jdbc.sql("UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'").update();
		}
		String action = switch (mode) {
			case "success" -> "password_authenticated";
			case "failure" -> "password_auth_failed";
			default -> "password_auth_throttled";
		};
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT authentication_test_reject CHECK (action <> '" + action + "') NOT VALID").update();
		var request = request("alice", mode.equals("failure") ? "wrong" : PASSWORD, context(1));
		try {
			assertThatThrownBy(() -> this.manager.authenticate(request)).isInstanceOf(AuthenticationServiceException.class)
					.hasMessage("Password authentication is unavailable");
			assertThat(request.getCredentials()).isNull();
			assertThat(sourceFailures()).isEqualTo(mode.equals("source-throttled") ? 50 : previous);
			assertThat(accountFailures()).isEqualTo(previous);
			assertThat(authEvents()).hasSize(previous);
		}
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT authentication_test_reject").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "success", "failure", "audit" })
	void silentlySuppressedCounterOrAuditWritesFailClosed(String mode) {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		String table = mode.equals("audit") ? "iam_security_audit" : "iam_password_authentication_limit";
		String mutation = mode.equals("audit") ? "INSERT" : "UPDATE";
		this.jdbc.sql("CREATE FUNCTION authentication_test_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
		try {
			this.jdbc.sql("CREATE TRIGGER authentication_test_suppress BEFORE " + mutation + " ON " + table
					+ " FOR EACH ROW EXECUTE FUNCTION authentication_test_suppress()").update();
			var request = request("alice", mode.equals("failure") ? "wrong" : PASSWORD, context(1));
			assertThatThrownBy(() -> this.manager.authenticate(request)).isInstanceOf(AuthenticationServiceException.class);
			assertThat(request.getCredentials()).isNull();
			assertThat(accountFailures()).isEqualTo(1);
			assertThat(sourceFailures()).isEqualTo(1);
			assertThat(authEvents()).hasSize(1);
		}
		finally {
			this.jdbc.sql("DROP TRIGGER IF EXISTS authentication_test_suppress ON " + table).update();
			this.jdbc.sql("DROP FUNCTION authentication_test_suppress()").update();
		}
	}

	@Test
	void counterDatabaseFailureRollsBackNewBucketsAndDoesNotLeaveFailureAudit() {
		activeUser("alice");
		this.jdbc.sql("ALTER TABLE iam_password_authentication_limit ADD CONSTRAINT authentication_test_reject CHECK (failures = 0)").update();
		try {
			assertThatThrownBy(() -> authenticate("alice", "wrong", context(1))).isInstanceOf(AuthenticationServiceException.class);
			assertThat(count("iam_password_authentication_limit")).isZero();
			assertThat(authEvents()).isEmpty();
		}
		finally { this.jdbc.sql("ALTER TABLE iam_password_authentication_limit DROP CONSTRAINT authentication_test_reject").update(); }
	}

	@Test
	void concurrentFailuresAcrossSourcesCannotExceedTheAccountLimit() throws Exception {
		activeUser("alice");
		for (int i = 0; i < 8; i++) { deny("alice", "wrong", context(1)); }
		runConcurrently(IntStream.range(0, 4).mapToObj(i -> (Callable<Boolean>) () -> {
			deny("alice", "wrong", context(i + 20)); return true;
		}).toList());
		assertThat(accountFailures()).isEqualTo(10);
		assertThat(sourceFailures()).isEqualTo(10);
		assertThat(authEvents()).filteredOn(e -> e.get("action").equals("password_auth_failed")).hasSize(10);
		assertThat(authEvents()).filteredOn(e -> e.get("action").equals("password_auth_throttled")).hasSize(2);
	}

	@Test
	void concurrentFailuresAcrossAccountsCannotExceedTheSourceLimit() throws Exception {
		for (int i = 0; i < 49; i++) { deny("unknown-" + i, PASSWORD, context(1)); }
		runConcurrently(IntStream.range(0, 3).mapToObj(i -> (Callable<Boolean>) () -> {
			deny("new-unknown-" + i, PASSWORD, context(1)); return true;
		}).toList());
		assertThat(sourceFailures()).isEqualTo(50);
		assertThat(authEvents()).filteredOn(e -> e.get("action").equals("password_auth_failed")).hasSize(50);
		assertThat(authEvents()).filteredOn(e -> e.get("action").equals("password_auth_throttled")).hasSize(2);
	}

	@Test
	void independentAccountsCanAuthenticateConcurrently() throws Exception {
		IdentityUser alice = activeUser("alice");
		IdentityUser bob = activeUser("bob");
		List<Authentication> results = runConcurrently(List.of(() -> authenticate("alice", PASSWORD, context(1)), () -> authenticate("bob", PASSWORD, context(2))));
		assertThat(results).extracting(Authentication::getPrincipal).containsExactly(alice.id(), bob.id());
		assertThat(authEvents()).hasSize(2);
	}

	@Test
	void rechecksAccountStatusAfterWaitingForTheUserLock() throws Exception {
		IdentityUser user = activeUser("alice");
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT id FROM iam_user WHERE id = ? FOR UPDATE")) {
				statement.setObject(1, user.id());
				try (var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
			}
			var waiting = executor.submit(() -> authenticate("alice", PASSWORD, context(1)));
			try {
				awaitBlockedBy(blocker);
				try (var statement = blocker.prepareStatement("UPDATE iam_user SET status = 'disabled' WHERE id = ?")) {
					statement.setObject(1, user.id()); statement.executeUpdate();
				}
				blocker.commit();
				assertThatThrownBy(() -> waiting.get(20, TimeUnit.SECONDS)).hasCauseInstanceOf(BadCredentialsException.class);
			}
			finally { blocker.rollback(); }
		}
		assertThat(authEvents().getFirst().get("action")).isEqualTo("password_auth_failed");
	}

	@ParameterizedTest
	@ValueSource(strings = { "block", "expire" })
	void rechecksCountersAndRealTimeAfterWaitingForTheSourceLock(String mode) throws Exception {
		activeUser("alice");
		deny("alice", "wrong", context(1));
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT subject_key FROM iam_password_authentication_limit WHERE dimension = 'source' FOR UPDATE");
					var result = statement.executeQuery()) { assertThat(result.next()).isTrue(); }
			var waiting = executor.submit(() -> authenticate("alice", PASSWORD, context(1)));
			try {
				awaitBlockedBy(blocker);
				String sql = mode.equals("block") ? "UPDATE iam_password_authentication_limit SET failures = 50 WHERE dimension = 'source'"
						: "UPDATE iam_password_authentication_limit SET failures = 50, window_started_at = clock_timestamp() - INTERVAL '5 minutes' WHERE dimension = 'source'";
				try (var statement = blocker.createStatement()) { statement.executeUpdate(sql); }
				blocker.commit();
				if (mode.equals("block")) {
					assertThatThrownBy(() -> waiting.get(20, TimeUnit.SECONDS)).hasCauseInstanceOf(BadCredentialsException.class);
					assertThat(sourceFailures()).isEqualTo(50);
				}
				else {
					assertThat(waiting.get(20, TimeUnit.SECONDS).isAuthenticated()).isTrue();
					assertThat(sourceFailures()).isZero();
				}
			}
			finally { blocker.rollback(); }
		}
	}

	@Test
	void restartedApplicationRetainsTheAccountLimit() {
		activeUser("alice");
		for (int i = 0; i < 10; i++) { deny("alice", "wrong", context(1)); }
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE)
				.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(),
						"spring.datasource.password", this.postgres.getPassword(), "spring.main.banner-mode", "off")).run()) {
			assertThatThrownBy(() -> restarted.getBean(AuthenticationManager.class).authenticate(request("alice", PASSWORD, context(2))))
					.isExactlyInstanceOf(BadCredentialsException.class).hasMessage("Invalid credentials");
		}
		assertThat(accountFailures()).isEqualTo(10);
		assertThat(authEvents().getLast().get("action")).isEqualTo("password_auth_throttled");
	}

	@Test
	void doesNotPersistPasswordsHashesNamesOrRawSourceAddressesInAuditOrCounters() {
		IdentityUser user = activeUser("alice");
		deny("alice", "wrong but long password", context(1));
		authenticate("alice", PASSWORD, context(1));
		for (String table : List.of("iam_security_audit", "iam_password_authentication_limit")) {
			assertThat(this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t").query(String.class).list())
					.allSatisfy(row -> assertThat(row).doesNotContain(PASSWORD, "wrong but long password", storedHash(user.id()), "alice", "192.0.2.1"));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"dimension = 'other'", "subject_key = 'plain-text'", "subject_key = repeat('A', 64)",
			"failures = -1", "failures = 11", "window_started_at = 'infinity'"
	})
	void databaseRejectsInvalidLimitRows(String mutation) {
		deny("unknown", PASSWORD, context(1));
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_password_authentication_limit SET " + mutation + " WHERE dimension = 'account'").update())
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void databaseEnforcesAuditTargetsAndActionOutcomePairs() {
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.audits.recordFailure(Action.PASSWORD_AUTH_FAILED, null, SYSTEM);
			this.audits.recordFailure(Action.PASSWORD_AUTH_THROTTLED, null, SYSTEM);
		});
		assertThat(authEvents()).hasSize(2);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET outcome = 'success'").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET action = 'user_created', outcome = 'success'").update())
				.isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.audits.recordSuccess(Action.PASSWORD_AUTH_FAILED, null, SYSTEM))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status ->
				this.audits.recordFailure(Action.USER_CREATED, UUID.randomUUID(), SYSTEM))).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void upgradesV3WithoutChangingExistingIdentityPasswordSetupOrAuditData() throws Exception {
		String schema = "authentication_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
					.schemas(schema).defaultSchema(schema).target("3").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID id = UUID.randomUUID();
				previous.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", id).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)")
						.param("id", id).param("hash", this.passwords.hash(PASSWORD, "alice")).update();
				previous.sql("""
						INSERT INTO iam_user_setup (user_id, token_digest, status, issued_at, expires_at)
						VALUES (:id, repeat('a', 64), 'issued', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 minutes')
						""").param("id", id).update();
				previous.sql("""
						INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
						VALUES (:event, 'system:upgrade-test', 'internal:test', :correlation, :user, 'user_created', 'success')
						""").param("event", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", id).update();
				var tables = List.of("iam_user", "iam_password", "iam_user_setup", "iam_security_audit");
				var before = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t").query(String.class).single()).toList();
				Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
						.schemas(schema).defaultSchema(schema).load().migrate();
				var after = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t").query(String.class).single()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(previous.sql("SELECT credential_version FROM iam_password").query(Long.class).single()).isEqualTo(1);
				assertThat(previous.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single()).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private IdentityUser activeUser(String username) {
		IdentityUser pending = this.users.create(username, "Private Display", SYSTEM);
		var proof = this.setups.issue(pending.id(), SYSTEM);
		this.setups.complete(pending.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		return this.users.findById(pending.id()).orElseThrow();
	}

	private PasswordAuthenticationContext context(int source) {
		try { return new PasswordAuthenticationContext("internal:password-test", InetAddress.getByAddress(new byte[] { (byte) 192, 0, 2, (byte) source }), UUID.randomUUID()); }
		catch (java.net.UnknownHostException ex) { throw new AssertionError(ex); }
	}

	private UsernamePasswordAuthenticationToken request(String username, String password, PasswordAuthenticationContext context) {
		var request = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
		request.setDetails(context);
		return request;
	}

	private Authentication authenticate(String username, String password, PasswordAuthenticationContext context) {
		return this.manager.authenticate(request(username, password, context));
	}

	private void deny(String username, String password, PasswordAuthenticationContext context) {
		assertThatThrownBy(() -> authenticate(username, password, context)).isExactlyInstanceOf(BadCredentialsException.class).hasMessage("Invalid credentials");
	}

	private List<Map<String, Object>> authEvents() {
		return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action LIKE 'password_%' ORDER BY recorded_at, id").query().listOfRows();
	}

	private int sourceFailures() {
		return this.jdbc.sql("SELECT COALESCE(sum(failures), 0) FROM iam_password_authentication_limit WHERE dimension = 'source'").query(Integer.class).single();
	}

	private int accountFailures() {
		return this.jdbc.sql("SELECT failures FROM iam_password_authentication_limit WHERE dimension = 'account'").query(Integer.class).single();
	}

	private String accountWindow() {
		return this.jdbc.sql("SELECT window_started_at::text FROM iam_password_authentication_limit WHERE dimension = 'account'").query(String.class).single();
	}

	private long count(String table) {
		return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
	}

	private String storedHash(UUID id) {
		return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id").param("id", id).query(String.class).single();
	}

	private void awaitBlockedBy(Connection blocker) {
		int pid = JdbcClient.create(new SingleConnectionDataSource(blocker, true)).sql("SELECT pg_backend_pid()").query(Integer.class).single();
		await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
				    AND :blocker = ANY(pg_blocking_pids(pid)))
				""").param("blocker", pid).query(Boolean.class).single());
	}

	private <T> List<T> runConcurrently(List<Callable<T>> operations) throws Exception {
		try (var executor = Executors.newFixedThreadPool(operations.size())) {
			CountDownLatch start = new CountDownLatch(1);
			var futures = operations.stream().map(op -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue(); return op.call();
			})).toList();
			start.countDown();
			var results = new java.util.ArrayList<T>();
			for (var future : futures) { results.add(future.get(20, TimeUnit.SECONDS)); }
			return results;
		}
	}

}
