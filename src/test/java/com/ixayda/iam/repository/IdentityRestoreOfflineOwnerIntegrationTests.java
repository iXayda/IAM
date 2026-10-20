package com.ixayda.iam.repository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdentityRestoreOfflineOwnerIntegrationTests {

	private final PostgreSQLContainer postgres = new PostgreSQLContainer(
			"postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
			.withCommand("postgres", "-c", "autovacuum_naptime=1s", "-c", "autovacuum_max_workers=1");
	private Connection owner;
	private JdbcClient jdbc;
	private IdentityRestoreRepository repository;

	@BeforeAll
	void startDatabase() throws SQLException {
		this.postgres.start(); openOwner();
		this.jdbc.sql("CREATE ROLE offline_owner LOGIN PASSWORD 'isolated-offline-password'").update();
		this.jdbc.sql("CREATE ROLE offline_operator LOGIN PASSWORD 'isolated-operator-password'").update();
		this.jdbc.sql("GRANT offline_owner TO offline_operator").update();
		this.jdbc.sql("CREATE DATABASE offline_owned OWNER offline_owner").update();
	}

	@AfterAll
	void stopDatabase() throws SQLException {
		try { if (this.owner != null) { this.owner.close(); } }
		finally { this.postgres.close(); }
	}

	@BeforeEach
	void awaitPreviousClientsDisconnect() {
		awaitOnlyClient(this.postgres.getDatabaseName());
	}

	@Test
	void acceptsTheConfirmedDatabaseOwnerWithNoOtherClients() {
		assertThatCode(() -> this.repository.requireOfflineOwner(this.postgres.getDatabaseName())).doesNotThrowAnyException();
	}

	@Test
	void rejectsAnUnconfirmedDatabase() {
		assertThatIllegalStateException().isThrownBy(() -> this.repository.requireOfflineOwner("another-database"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "offline-client", "autovacuum worker" })
	void rejectsAnotherClientEvenWhenItsApplicationNameImpersonatesAutovacuum(String applicationName) throws SQLException {
		try (var other = connection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			JdbcClient client = jdbc(other);
			client.sql("SELECT set_config('application_name',:name,false)").param("name", applicationName).query(String.class).single();
			int pid = client.sql("SELECT pg_backend_pid()").query(Integer.class).single();
			assertThat(this.jdbc.sql("SELECT backend_type FROM pg_stat_activity WHERE pid=:pid").param("pid", pid).query(String.class).single())
					.isEqualTo("client backend");
			assertThatIllegalStateException().isThrownBy(() -> this.repository.requireOfflineOwner(this.postgres.getDatabaseName()));
		}
	}

	@Test
	void rejectsANonOwnerEvenWithNoOtherClient() throws SQLException {
		int ownerPid = this.jdbc.sql("SELECT pg_backend_pid()").query(Integer.class).single();
		this.owner.close();
		try (var nonOwner = connection(this.postgres.getJdbcUrl(), "offline_owner", "isolated-offline-password")) {
			JdbcClient client = jdbc(nonOwner);
			await().atMost(Duration.ofSeconds(5)).until(() -> client.sql("SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=:pid)")
					.param("pid", ownerPid).query(Boolean.class).single());
			var repository = new IdentityRestoreRepository(client);
			assertThatIllegalStateException().isThrownBy(() -> repository.requireOfflineOwner(this.postgres.getDatabaseName()));
		}
		finally { openOwner(); }
	}

	@Test
	void rejectsAChangedSessionRoleEvenWhenItAssumesDatabaseOwnership() throws SQLException {
		try (var operator = connection(ownedDatabaseUrl(), "offline_operator", "isolated-operator-password")) {
			awaitOnlyClient("offline_owned");
			JdbcClient client = jdbc(operator); client.sql("SET ROLE offline_owner").update();
			assertThat(client.sql("SELECT current_user<>session_user AND current_user=pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
					.query(Boolean.class).single()).isTrue();
			assertThatIllegalStateException().isThrownBy(() -> new IdentityRestoreRepository(client).requireOfflineOwner("offline_owned"));
		}
	}

	@Test
	void anOrdinaryOwnerStillRejectsABackendWhoseTypeIsHidden() throws SQLException {
		try (var ordinaryOwner = connection(ownedDatabaseUrl(), "offline_owner", "isolated-offline-password");
				var other = connection(ownedDatabaseUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			JdbcClient restricted = jdbc(ordinaryOwner);
			int pid = jdbc(other).sql("SELECT pg_backend_pid()").query(Integer.class).single();
			assertThat(restricted.sql("SELECT current_user=pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")
					.query(Boolean.class).single()).isTrue();
			assertThat(restricted.sql("SELECT backend_type IS NULL FROM pg_stat_activity WHERE pid=:pid").param("pid", pid)
					.query(Boolean.class).single()).isTrue();
			assertThatIllegalStateException().isThrownBy(() -> new IdentityRestoreRepository(restricted).requireOfflineOwner("offline_owned"));
		}
	}

	@Test
	void permitsARealAutovacuumWorkerWithoutPermittingAnotherClient() throws SQLException {
		this.jdbc.sql("CREATE TABLE offline_autovacuum_probe(id integer,padding text) WITH (autovacuum_enabled=false)").update();
		try {
			this.jdbc.sql("INSERT INTO offline_autovacuum_probe SELECT n,repeat('x',1000) FROM generate_series(1,4096) n").update();
			this.jdbc.sql("DELETE FROM offline_autovacuum_probe WHERE id%2=0").update();
			// Slow the real worker long enough to check admission while VACUUM is still running.
			this.jdbc.sql("""
					ALTER TABLE offline_autovacuum_probe SET (autovacuum_enabled=true,
					    autovacuum_vacuum_threshold=0,autovacuum_vacuum_scale_factor=0,
					    autovacuum_vacuum_cost_delay=100,autovacuum_vacuum_cost_limit=1)
					""").update();
			this.jdbc.sql("SELECT pg_stat_force_next_flush()").query((row, index) -> true).single();
			await().pollInterval(Duration.ofMillis(100)).atMost(Duration.ofSeconds(20)).until(this::autovacuumIsRunning);
			assertThatCode(() -> this.repository.requireOfflineOwner(this.postgres.getDatabaseName())).doesNotThrowAnyException();
			assertThat(autovacuumIsRunning()).isTrue();
			try (var other = connection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				assertThatIllegalStateException().isThrownBy(() -> this.repository.requireOfflineOwner(this.postgres.getDatabaseName()));
			}
		}
		finally {
			// DROP obtains an exclusive lock and cancels ordinary autovacuum if it is still active.
			this.jdbc.sql("DROP TABLE offline_autovacuum_probe").update();
		}
	}

	private boolean autovacuumIsRunning() {
		return this.jdbc.sql("""
				SELECT EXISTS (SELECT 1 FROM pg_stat_activity a JOIN pg_stat_progress_vacuum v USING(pid)
				    WHERE a.datid=(SELECT oid FROM pg_database WHERE datname=current_database())
				        AND a.backend_type='autovacuum worker' AND v.relid='offline_autovacuum_probe'::regclass)
				""").query(Boolean.class).single();
	}

	private void openOwner() throws SQLException {
		this.owner = connection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
		this.jdbc = jdbc(this.owner); this.repository = new IdentityRestoreRepository(this.jdbc);
		this.jdbc.sql("SET lock_timeout='5s'").update();
	}

	private String ownedDatabaseUrl() {
		return this.postgres.getJdbcUrl().replace("/" + this.postgres.getDatabaseName(), "/offline_owned");
	}

	private void awaitOnlyClient(String database) {
		await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("""
				SELECT count(*) FROM pg_stat_activity WHERE datname=:database AND backend_type='client backend'
				""").param("database", database).query(Long.class).single() == 1);
	}

	private static Connection connection(String url, String username, String password) throws SQLException {
		return DriverManager.getConnection(url, username, password);
	}

	private static JdbcClient jdbc(Connection connection) {
		return JdbcClient.create(new SingleConnectionDataSource(connection, true));
	}

}
