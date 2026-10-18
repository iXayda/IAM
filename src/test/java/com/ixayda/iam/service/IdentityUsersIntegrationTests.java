package com.ixayda.iam.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.sql.DataSource;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;
import com.ixayda.iam.credential.PasswordRejectedException;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;

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
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@Import(PostgreSqlTestConfiguration.class)
class IdentityUsersIntegrationTests {

	private final SecurityAuditContext audit = new SecurityAuditContext("system:integration-test", "integration-test", UUID.randomUUID());

	@Autowired
	private IdentityUsers users;

	@Autowired
	private JdbcClient jdbc;

	@Autowired
	private PasswordHasher passwords;

	@Autowired
	private DataSource dataSource;

	@Autowired
	private PlatformTransactionManager transactions;

	@Autowired
	private PostgreSQLContainer postgres;

	@BeforeEach
	void removeTestUsers() {
		this.jdbc.sql("DELETE FROM iam_security_audit").update();
		this.jdbc.sql("DELETE FROM iam_user_setup").update();
		this.jdbc.sql("DELETE FROM iam_password").update();
		this.jdbc.sql("DELETE FROM iam_user").update();
	}

	@Test
	void createsPendingUsersWithStableIdsAndNormalizedNames() {
		IdentityUser first = this.users.create("Alice.Example", "Cafe\u0301 用户 😀", this.audit);
		IdentityUser second = this.users.create("another-user", "Another User", this.audit);
		assertThat(first.id()).isNotNull().isNotEqualTo(second.id());
		assertThat(first.username()).isEqualTo("alice.example");
		assertThat(first.displayName()).isEqualTo("Café 用户 😀");
		assertThat(first.status()).isEqualTo(IdentityUser.Status.PENDING);
		assertThat(first.createdAt()).isCloseTo(Instant.now(), within(10, java.time.temporal.ChronoUnit.SECONDS));
		assertThat(this.users.findById(first.id())).contains(first);
		assertThat(this.users.findByUsername("ALICE.EXAMPLE")).contains(first);
		assertThat(count("iam_password")).isZero();
	}

	@Test
	void supportsUsernameAndUnicodeDisplayNameLengthBoundariesWithoutTrimming() {
		assertThat(this.users.create("A.1", " 名 ", this.audit).displayName()).isEqualTo(" 名 ");
		assertThat(this.users.create("x".repeat(64), "😀".repeat(128), this.audit).displayName()).isEqualTo("😀".repeat(128));
		assertThatThrownBy(() -> this.users.create("x".repeat(65), "Valid Name", this.audit))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.users.create("valid-name", "😀".repeat(129), this.audit))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "ab", " alice", "alice ", "a b", "álîce", "Ａlice", "alice@example.com", "alice'--" })
	void rejectsInvalidUsernamesBeforeWriting(String username) {
		assertThatThrownBy(() -> this.users.create(username, "Valid Name", this.audit))
				.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.users.findByUsername(username)).isInstanceOf(IllegalArgumentException.class);
		assertThat(count("iam_user")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", "\u00a0", "\u0085", "\u202f", "line\nbreak", "null\u0000byte", "bad\ud800", "bad\udc00" })
	void rejectsInvalidDisplayNamesBeforeWriting(String displayName) {
		assertThatThrownBy(() -> this.users.create("alice", displayName, this.audit)).isInstanceOf(IllegalArgumentException.class);
		assertThat(count("iam_user")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@Test
	void storesDisplayNamesAsDataAndReportsMissingUsersWithoutCreatingThem() {
		String displayName = "'; DROP TABLE iam_user; --";
		IdentityUser user = this.users.create("alice", displayName, this.audit);
		assertThat(this.users.findById(user.id()).orElseThrow().displayName()).isEqualTo(displayName);
		assertThat(this.users.findById(UUID.randomUUID())).isEmpty();
		assertThat(this.users.findByUsername("missing")).isEmpty();
		assertThatThrownBy(() -> this.users.findById(null)).isInstanceOf(IllegalArgumentException.class);
		assertThat(count("iam_user")).isEqualTo(1);
	}

	@Test
	void duplicateUsernamesRemainReservedRegardlessOfCaseAndStatus() {
		IdentityUser user = this.users.create("Alice", "Alice", this.audit);
		this.jdbc.sql("UPDATE iam_user SET status = 'disabled' WHERE id = :id").param("id", user.id()).update();
		assertThatThrownBy(() -> this.users.create("ALICE", "Another Alice", this.audit)).isInstanceOf(DuplicateKeyException.class);
		assertThat(this.users.findById(user.id()).orElseThrow().status()).isEqualTo(IdentityUser.Status.DISABLED);
		assertThat(count("iam_user")).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@Test
	void storesOnlyAnArgon2HashAndKeepsTheUserPending() {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		String password = " Seven amber lanterns by the Café ";
		this.users.setInitialPassword(user.id(), password, this.audit);
		String hash = storedPassword(user.id());
		assertThat(hash).startsWith("$argon2id$v=19$m=19456,t=2,p=1$").doesNotContain(password);
		assertThat(this.passwords.matches(password, hash)).isTrue();
		assertThat(this.passwords.matches(password.strip(), hash)).isFalse();
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(count("iam_password")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "hash", "version" })
	void initialPasswordStorageMustMatchTheRequestedCredential(String fault) {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		String password = "seven amber lanterns by the river";
		String mutation = switch (fault) {
			case "missing" -> "RETURN NULL;";
			case "hash" -> "NEW.password_hash = '" + this.passwords.hash("seven silver lanterns on the hill", user.username()) + "'; RETURN NEW;";
			case "version" -> "NEW.credential_version = 2; RETURN NEW;";
			default -> throw new AssertionError(fault);
		};
		this.jdbc.sql("CREATE FUNCTION initial_password_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + mutation + " END $$").update();
		this.jdbc.sql("CREATE TRIGGER initial_password_fault BEFORE INSERT ON iam_password FOR EACH ROW EXECUTE FUNCTION initial_password_fault()").update();
		try {
			assertThatIllegalStateException().isThrownBy(() -> this.users.setInitialPassword(user.id(), password, this.audit));
		}
		finally { this.jdbc.sql("DROP FUNCTION initial_password_fault() CASCADE").update(); }
		assertThat(this.users.findById(user.id())).contains(user);
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isEqualTo(1);
		this.users.setInitialPassword(user.id(), password, this.audit);
		assertThat(this.passwords.matches(password, storedPassword(user.id()))).isTrue();
		assertThat(this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", user.id()).query(Long.class).single()).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void initialPasswordCannotReplaceAnExistingCredential() {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit);
		String original = storedPassword(user.id());
		assertThatThrownBy(() -> this.users.setInitialPassword(user.id(), "seven silver lanterns on the hill", this.audit))
				.isInstanceOf(DuplicateKeyException.class);
		assertThat(storedPassword(user.id())).isEqualTo(original);
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void appliesPasswordRulesUsingThePersistedUsernameWithoutLeavingPartialCredentials() {
		IdentityUser user = this.users.create("LongAccountName15", "Alice", this.audit);
		for (String password : new String[] { null, "short", "passwordpassword", "LONGACCOUNTNAME15123!" }) {
			assertThatThrownBy(() -> this.users.setInitialPassword(user.id(), password, this.audit))
					.isInstanceOf(PasswordRejectedException.class);
			assertThat(count("iam_password")).isZero();
			assertThat(this.users.findById(user.id())).contains(user);
			assertThat(count("iam_security_audit")).isEqualTo(1);
		}
		this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit);
		assertThat(count("iam_password")).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "active", "disabled" })
	void refusesInitialPasswordsForUsersWhoAreNotPending(String state) {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		this.jdbc.sql("UPDATE iam_user SET status = :state WHERE id = :id")
				.param("state", state).param("id", user.id()).update();
		assertThatThrownBy(() -> this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit))
				.isInstanceOf(IllegalStateException.class);
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@Test
	void refusesPasswordWritesForMissingUsers() {
		assertThatThrownBy(() -> this.users.setInitialPassword(UUID.randomUUID(), "seven amber lanterns by the river", this.audit))
				.isInstanceOf(NoSuchElementException.class);
		assertThatThrownBy(() -> this.users.setInitialPassword(null, "seven amber lanterns by the river", this.audit))
				.isInstanceOf(IllegalArgumentException.class);
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@Test
	void participatesInTheCallersTransactionForAtomicUserAndCredentialWrites() {
		var id = new AtomicReference<UUID>();
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(transaction -> {
			IdentityUser user = this.users.create("alice", "Alice", this.audit);
			id.set(user.id());
			this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit);
			throw new IllegalStateException("Rollback the complete operation");
		})).isInstanceOf(IllegalStateException.class).hasMessage("Rollback the complete operation");
		assertThat(this.users.findById(id.get())).isEmpty();
		assertThat(count("iam_user")).isZero();
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@Test
	void databaseConstraintsRejectInvalidNamesStatesOrphanCredentialsAndPlaintext() {
		assertThatThrownBy(() -> this.jdbc.sql("""
				INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'Alice', 'Alice')
				""").param("id", UUID.randomUUID()).update()).isInstanceOf(DataIntegrityViolationException.class);
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_user SET status = 'unknown' WHERE id = :id")
				.param("id", user.id()).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("""
				INSERT INTO iam_password (user_id, password_hash) VALUES (:id, 'plaintext password')
				""").param("id", user.id()).update()).isInstanceOf(DataIntegrityViolationException.class);
		String hash = this.passwords.hash("seven amber lanterns by the river", "alice");
		assertThatThrownBy(() -> this.jdbc.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)")
				.param("id", UUID.randomUUID()).param("hash", hash).update())
				.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(count("iam_password")).isZero();
	}

	@Test
	void concurrentCreatesHaveExactlyOneWinner() throws Exception {
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			Callable<String> create = () -> {
				if (!start.await(10, TimeUnit.SECONDS)) {
					throw new AssertionError("Concurrent create did not start");
				}
				try {
					this.users.create("Alice", "Alice", this.audit);
					return "created";
				}
				catch (DuplicateKeyException ex) {
					return "duplicate";
				}
			};
			var first = executor.submit(create);
			var second = executor.submit(create);
			start.countDown();
			assertThat(List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS)))
					.containsExactlyInAnyOrder("created", "duplicate");
		}
		assertThat(count("iam_user")).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@Test
	void concurrentInitialPasswordsHaveExactlyOneWinnerWithoutOverwriting() throws Exception {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		var start = new CountDownLatch(1);
		String firstPassword = "seven amber lanterns by the river";
		String secondPassword = "seven silver lanterns on the hill";
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> saveConcurrently(user.id(), firstPassword, start));
			var second = executor.submit(() -> saveConcurrently(user.id(), secondPassword, start));
			start.countDown();
			String firstResult = first.get(20, TimeUnit.SECONDS);
			String secondResult = second.get(20, TimeUnit.SECONDS);
			assertThat(List.of(firstResult, secondResult)).containsExactlyInAnyOrder("saved", "duplicate");
			String hash = storedPassword(user.id());
			assertThat(this.passwords.matches(firstPassword, hash)).isEqualTo(firstResult.equals("saved"));
			assertThat(this.passwords.matches(secondPassword, hash)).isEqualTo(secondResult.equals("saved"));
		}
		assertThat(count("iam_password")).isEqualTo(1);
		assertThat(count("iam_security_audit")).isEqualTo(2);
	}

	@Test
	void rechecksStatusAfterWaitingForTheUserRowLock() throws Exception {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		try (var blocker = this.dataSource.getConnection(); var executor = Executors.newSingleThreadExecutor()) {
			blocker.setAutoCommit(false);
			try (var statement = blocker.prepareStatement("SELECT id FROM iam_user WHERE id = ? FOR UPDATE")) {
				statement.setObject(1, user.id());
				try (var result = statement.executeQuery()) {
					assertThat(result.next()).isTrue();
				}
			}
			var waiting = executor.submit(() -> this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit));
			try {
				await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(this.jdbc.sql("""
						SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
						AND wait_event_type = 'Lock' AND query LIKE '%FROM iam_user WHERE id = %FOR UPDATE%'
						""").query(Long.class).single()).isEqualTo(1));
				try (var statement = blocker.prepareStatement("UPDATE iam_user SET status = 'disabled' WHERE id = ?")) {
					statement.setObject(1, user.id());
					statement.executeUpdate();
				}
				blocker.commit();
				assertThatThrownBy(() -> waiting.get(20, TimeUnit.SECONDS)).hasCauseInstanceOf(IllegalStateException.class);
			}
			finally {
				blocker.rollback();
			}
		}
		assertThat(count("iam_password")).isZero();
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@Test
	void aNewApplicationContextReadsExistingUsersAndDoesNotRepeatTheMigration() {
		IdentityUser user = this.users.create("alice", "Alice", this.audit);
		this.users.setInitialPassword(user.id(), "seven amber lanterns by the river", this.audit);
		String hash = storedPassword(user.id());
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE)
				.properties(Map.of("spring.datasource.url", this.postgres.getJdbcUrl(),
						"spring.datasource.username", this.postgres.getUsername(),
						"spring.datasource.password", this.postgres.getPassword(), "spring.main.banner-mode", "off"))
				.run()) {
			assertThat(restarted.getBean(IdentityUsers.class).findById(user.id())).contains(user);
			assertThat(restarted.getBean(PasswordHasher.class).matches("seven amber lanterns by the river", hash)).isTrue();
			assertThat(restarted.getBean(JdbcClient.class).sql("SELECT count(*) FROM iam_security_audit WHERE target_user_id = :id")
					.param("id", user.id()).query(Long.class).single()).isEqualTo(2);
			assertThat(this.jdbc.sql("SELECT count(*) FROM flyway_schema_history WHERE success AND version IN ('1', '2')")
					.query(Long.class).single()).isEqualTo(2);
		}
		assertThat(storedPassword(user.id())).isEqualTo(hash);
	}

	private String saveConcurrently(UUID id, String password, CountDownLatch start) throws InterruptedException {
		if (!start.await(10, TimeUnit.SECONDS)) {
			throw new AssertionError("Concurrent password write did not start");
		}
		try {
			this.users.setInitialPassword(id, password, this.audit);
			return "saved";
		}
		catch (DuplicateKeyException ex) {
			return "duplicate";
		}
	}

	private String storedPassword(UUID id) {
		return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id = :id")
				.param("id", id).query(String.class).single();
	}

	private long count(String table) {
		return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
	}

}
