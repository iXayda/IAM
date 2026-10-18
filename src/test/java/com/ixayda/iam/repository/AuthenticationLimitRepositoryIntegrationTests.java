package com.ixayda.iam.repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;
import java.util.stream.Stream;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthenticationLimitRepositoryIntegrationTests {

	private static final String KEY = "a".repeat(64);
	private static final int GATE = 63129;

	private final PostgreSQLContainer postgres = new PostgreSQLContainer(
			"postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");
	private Connection observer;
	private JdbcClient jdbc;

	@BeforeAll
	void startDatabase() throws SQLException {
		this.postgres.start();
		Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).load().migrate();
		this.observer = connection(); this.jdbc = jdbc(this.observer);
		this.jdbc.sql("""
				CREATE FUNCTION limit_insert_gate() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
				    PERFORM pg_advisory_xact_lock(63129, 1);
				    RETURN NULL;
				END $$
				""").update();
		this.jdbc.sql("CREATE FUNCTION suppress_limit_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
	}

	@AfterAll
	void stopDatabase() throws SQLException {
		try { if (this.observer != null) { this.observer.close(); } }
		finally { this.postgres.close(); }
	}

	@ParameterizedTest
	@EnumSource(Limit.class)
	void cleanupCannotDeleteAnExpiredBucketDuringAdmission(Limit limit) throws Exception {
		seed(limit, "clock_timestamp() - INTERVAL '2 days'", 3);
		// A statement trigger also runs for ON CONFLICT, after the admission statement has handled the existing row.
		this.jdbc.sql("CREATE TRIGGER pause_admission AFTER INSERT ON " + limit.table
				+ " FOR EACH STATEMENT EXECUTE FUNCTION limit_insert_gate()").update();
		try (var gate = connection(); var admission = connection()) {
			gate.setAutoCommit(false); admission.setAutoCommit(false);
			int gatePid = jdbc(gate).sql("SELECT pg_backend_pid()").query(Integer.class).single();
			jdbc(gate).sql("SELECT pg_advisory_xact_lock(:gate, 1)").param("gate", GATE).query((row, index) -> true).single();
			try (var executor = Executors.newSingleThreadExecutor()) {
				try {
					var attempt = executor.submit(() -> {
						int failures = limit.repository(jdbc(admission)).lock.getAsInt();
						admission.commit();
						return failures;
					});
					awaitBlockedBy(gatePid);
					limit.repository(this.jdbc).cleanup.run();
					gate.rollback();
					assertThat(attempt.get(10, TimeUnit.SECONDS)).isZero();
					assertThat(count(limit)).isEqualTo(1);
					assertThat(failures(limit)).isZero();
					assertThat(this.jdbc.sql("SELECT window_started_at > clock_timestamp() - INTERVAL '1 minute' FROM " + limit.table)
							.query(Boolean.class).single()).isTrue();
				}
				finally { gate.rollback(); }
			}
		}
		finally {
			this.jdbc.sql("DROP TRIGGER pause_admission ON " + limit.table).update();
			this.jdbc.sql("DELETE FROM " + limit.table).update();
		}
	}

	@ParameterizedTest
	@EnumSource(Limit.class)
	void admissionRecreatesTheBucketAfterCleanupCommits(Limit limit) throws Exception {
		seed(limit, "clock_timestamp() - INTERVAL '2 days'", 3);
		try (var cleanup = connection(); var admission = connection()) {
			cleanup.setAutoCommit(false); admission.setAutoCommit(false);
			var cleaner = jdbc(cleanup);
			int cleanupPid = cleaner.sql("SELECT pg_backend_pid()").query(Integer.class).single();
			limit.repository(cleaner).cleanup.run();
			try (var executor = Executors.newSingleThreadExecutor()) {
				try {
					var attempt = executor.submit(() -> {
						var repository = limit.repository(jdbc(admission));
						int failures = repository.lock.getAsInt();
						repository.recordFailure.run();
						admission.commit();
						return failures;
					});
					awaitBlockedBy(cleanupPid);
					cleanup.commit();
					assertThat(attempt.get(10, TimeUnit.SECONDS)).isZero();
					assertThat(count(limit)).isEqualTo(1);
					assertThat(failures(limit)).isEqualTo(1);
				}
				finally { cleanup.rollback(); }
			}
		}
	}

	@ParameterizedTest
	@EnumSource(Limit.class)
	void concurrentAdmissionsPreserveTheActiveWindowAndFailureBudget(Limit limit) throws Exception {
		seed(limit, "clock_timestamp()", 3);
		String startedAt = this.jdbc.sql("SELECT window_started_at::text FROM " + limit.table).query(String.class).single();
		try (var first = connection(); var second = connection()) {
			first.setAutoCommit(false); second.setAutoCommit(false);
			var firstClient = jdbc(first);
			int firstPid = firstClient.sql("SELECT pg_backend_pid()").query(Integer.class).single();
			var firstRepository = limit.repository(firstClient);
			assertThat(firstRepository.lock.getAsInt()).isEqualTo(3);
			firstRepository.recordFailure.run();
			try (var executor = Executors.newSingleThreadExecutor()) {
				try {
					var attempt = executor.submit(() -> {
						var repository = limit.repository(jdbc(second));
						int failures = repository.lock.getAsInt();
						repository.recordFailure.run();
						second.commit();
						return failures;
					});
					awaitBlockedBy(firstPid);
					first.commit();
					assertThat(attempt.get(10, TimeUnit.SECONDS)).isEqualTo(4);
					assertThat(failures(limit)).isEqualTo(5);
					assertThat(this.jdbc.sql("SELECT window_started_at::text FROM " + limit.table).query(String.class).single()).isEqualTo(startedAt);
				}
				finally { first.rollback(); }
			}
		}
	}

	@ParameterizedTest
	@MethodSource("suppressedAdmissions")
	void suppressedAdmissionFailsAndRollsBackTheTransaction(Limit limit, String operation) throws SQLException {
		this.jdbc.sql("DELETE FROM " + limit.table).update();
		if (operation.equals("UPDATE")) { seed(limit, "clock_timestamp()", 3); }
		this.jdbc.sql("CREATE TRIGGER suppress_admission BEFORE " + operation + " ON " + limit.table
				+ " FOR EACH ROW WHEN (NEW.subject_key='" + KEY + "') EXECUTE FUNCTION suppress_limit_write()").update();
		try (var connection = connection()) {
			var dataSource = new SingleConnectionDataSource(connection, true);
			var transactional = JdbcClient.create(dataSource);
			var transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
			assertThatIllegalStateException().isThrownBy(() -> transaction.executeWithoutResult(status -> {
				transactional.sql("INSERT INTO " + limit.table + " (dimension, subject_key) VALUES ('source', :key)")
						.param("key", "b".repeat(64)).update();
				limit.repository(transactional).lock.getAsInt();
			})).withMessageContaining("limit was not stored");
			assertThat(count(limit)).isEqualTo(operation.equals("UPDATE") ? 1 : 0);
			if (operation.equals("UPDATE")) { assertThat(failures(limit)).isEqualTo(3); }
		}
		finally {
			this.jdbc.sql("DROP TRIGGER suppress_admission ON " + limit.table).update();
			this.jdbc.sql("DELETE FROM " + limit.table).update();
		}
	}

	private static Stream<Arguments> suppressedAdmissions() {
		return Stream.of(Limit.values()).flatMap(limit -> Stream.of("INSERT", "UPDATE").map(operation -> Arguments.of(limit, operation)));
	}

	private void seed(Limit limit, String window, int failures) {
		this.jdbc.sql("DELETE FROM " + limit.table).update();
		this.jdbc.sql("INSERT INTO " + limit.table + " (dimension, subject_key, window_started_at, failures) VALUES ('account', :key, " + window + ", :failures)")
				.param("key", KEY).param("failures", failures).update();
	}

	private long count(Limit limit) {
		return this.jdbc.sql("SELECT count(*) FROM " + limit.table).query(Long.class).single();
	}

	private int failures(Limit limit) {
		return this.jdbc.sql("SELECT failures FROM " + limit.table).query(Integer.class).single();
	}

	private void awaitBlockedBy(int pid) {
		await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE :pid = ANY(pg_blocking_pids(pid)))")
				.param("pid", pid).query(Boolean.class).single());
	}

	private Connection connection() throws SQLException {
		var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
		jdbc(connection).sql("SET statement_timeout = '15s'").update();
		return connection;
	}

	private static JdbcClient jdbc(Connection connection) {
		return JdbcClient.create(new SingleConnectionDataSource(connection, true));
	}

	private record Repository(IntSupplier lock, Runnable recordFailure, Runnable cleanup) { }

	private enum Limit {
		PASSWORD("iam_password_authentication_limit"),
		TOTP("iam_totp_authentication_limit"),
		MFA_RECOVERY("iam_mfa_recovery_limit");

		private final String table;

		Limit(String table) { this.table = table; }

		Repository repository(JdbcClient jdbc) {
			return switch (this) {
				case PASSWORD -> {
					var repository = new PasswordAuthenticationLimitRepository(jdbc);
					yield new Repository(() -> repository.lockLimit("account", KEY, 300), () -> repository.recordFailure("account", KEY), repository::cleanUpExpired);
				}
				case TOTP -> {
					var repository = new TotpAuthenticationLimitRepository(jdbc);
					yield new Repository(() -> repository.lockLimit("account", KEY), () -> repository.recordFailure("account", KEY), repository::cleanUpExpired);
				}
				case MFA_RECOVERY -> {
					var repository = new MfaRecoveryCodeLimitRepository(jdbc);
					yield new Repository(() -> repository.lockLimit("account", KEY), () -> repository.recordFailure("account", KEY), repository::cleanUpExpired);
				}
			};
		}
	}

}
