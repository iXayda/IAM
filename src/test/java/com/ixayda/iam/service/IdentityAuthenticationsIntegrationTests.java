package com.ixayda.iam.service;

import java.sql.DriverManager;

import com.ixayda.iam.PostgreSqlTestConfiguration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthenticationsIntegrationTests {

	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private IdentityAuthentications authentications;
	@Autowired
	private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() { this.jdbc.sql("DELETE FROM iam_password_authentication_limit").update(); }

	@Test
	void counterCleanupIsBoundedRetainsCurrentWindowsAndSkipsLockedRows() throws Exception {
		this.jdbc.sql("""
				INSERT INTO iam_password_authentication_limit (dimension, subject_key, window_started_at)
				SELECT 'account', md5(i::text) || md5(i::text), clock_timestamp() - INTERVAL '2 days'
				FROM generate_series(1, 1002) i
				""").update();
		this.jdbc.sql("INSERT INTO iam_password_authentication_limit (dimension, subject_key) VALUES ('source', repeat('a', 64))").update();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			connection.setAutoCommit(false);
			try (var statement = connection.createStatement(); var result = statement.executeQuery(
					"SELECT subject_key FROM iam_password_authentication_limit WHERE dimension = 'account' ORDER BY subject_key LIMIT 1 FOR UPDATE")) {
				assertThat(result.next()).isTrue();
				String locked = result.getString(1);
				this.authentications.cleanUpExpiredLimits();
				assertThat(counterCount()).isEqualTo(3);
				this.authentications.cleanUpExpiredLimits();
				assertThat(counterCount()).isEqualTo(2);
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit WHERE subject_key = :key")
						.param("key", locked).query(Long.class).single()).isEqualTo(1);
			}
			finally { connection.rollback(); }
		}
		this.authentications.cleanUpExpiredLimits();
		assertThat(counterCount()).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT dimension FROM iam_password_authentication_limit").query(String.class).single()).isEqualTo("source");
	}

	private long counterCount() { return this.jdbc.sql("SELECT count(*) FROM iam_password_authentication_limit").query(Long.class).single(); }
}
