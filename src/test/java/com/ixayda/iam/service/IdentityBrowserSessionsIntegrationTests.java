package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.PasswordHasher;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityBrowserSessionsIntegrationTests {

	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private IdentityBrowserSessions sessions;
	@Autowired
	private PostgreSQLContainer postgres;
	@Autowired
	private PasswordHasher passwords;

	@Test
	void entryThrottlingHasNoInventedUserAndRequiresDurableAudit() {
		this.sessions.recordEntryThrottle();
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action = 'browser_entry_throttled'").query().singleRow();
		assertThat(event.get("actor")).isEqualTo("anonymous");
		assertThat(event.get("target_user_id")).isNull();
		assertThat(event.get("outcome")).isEqualTo("failure");
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_security_audit SET outcome = 'success' WHERE action = 'browser_entry_throttled'").update())
				.isInstanceOf(DataIntegrityViolationException.class);
		this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT browser_test_reject CHECK (action <> 'browser_entry_throttled') NOT VALID").update();
		try { assertThatThrownBy(this.sessions::recordEntryThrottle).isInstanceOf(DataIntegrityViolationException.class); }
		finally { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT browser_test_reject").update(); }
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'browser_entry_throttled'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void upgradingV4PreservesExistingRecordsAndCreatesOnlyTheNewSessionStorage() throws Exception {
		String schema = "session_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "4").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				JdbcClient previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				UUID id = UUID.randomUUID();
				previous.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", id).update();
				previous.sql("INSERT INTO iam_password (user_id, password_hash) VALUES (:id, :hash)").param("id", id)
						.param("hash", this.passwords.hash("Seven amber lanterns by the Café", "alice")).update();
				previous.sql("""
						INSERT INTO iam_user_setup (user_id, token_digest, status, issued_at, expires_at)
						VALUES (:id, repeat('a', 64), 'issued', clock_timestamp(), clock_timestamp() + INTERVAL '30 minutes')
						""").param("id", id).update();
				previous.sql("""
						INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome)
						VALUES (:id, 'system:upgrade', 'internal:test', :correlation, :user, 'user_created', 'success')
						""").param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", id).update();
				previous.sql("INSERT INTO iam_password_authentication_limit (dimension, subject_key, failures) VALUES ('source', repeat('a', 64), 3)").update();
				var tables = List.of("iam_user", "iam_password", "iam_user_setup", "iam_security_audit", "iam_password_authentication_limit");
				var before = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t").query(String.class).single()).toList();
				flyway(schema, "latest").migrate();
				var after = tables.stream().map(t -> previous.sql("SELECT (to_jsonb(t) - 'credential_version')::text FROM " + t + " t").query(String.class).single()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(previous.sql("SELECT credential_version FROM iam_password").query(Long.class).single()).isEqualTo(1);
				assertThat(previous.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
				assertThat(previous.sql("SELECT count(*) FROM iam_browser_session_attributes").query(Long.class).single()).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}
}
