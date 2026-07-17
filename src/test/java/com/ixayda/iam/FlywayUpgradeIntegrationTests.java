package com.ixayda.iam;

import java.util.UUID;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class FlywayUpgradeIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID TENANT_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742901");

	private static final UUID USER_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742902");

	private static final UUID CLIENT_ID = UUID.fromString("019c61d7-47d1-79ca-8052-1b731e742903");

	@Autowired
	private DataSource dataSource;

	@Test
	void upgradesStoredDataFromTheHistoricalUserSchemaToTheCurrentSchema() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "3");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(3);
			insertHistoricalData(jdbc, schema);

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isEqualTo(10);

			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(13);
			assertThat(count(jdbc, schema, "tenants")).isEqualTo(2);
			assertThat(count(jdbc, schema, "users")).isOne();
			assertThat(identifier(jdbc, schema)).isEqualTo("Alice@example.com|alice@example.com");
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	@Test
	void upgradesExistingClientsWithRefreshTokensDisabled() {
		String schema = "upgrade_" + UUID.randomUUID().toString().replace("-", "");
		JdbcClient jdbc = JdbcClient.create(this.dataSource);
		try {
			Flyway historical = flyway(schema, "12");
			assertThat(historical.migrate().migrationsExecuted).isEqualTo(12);
			jdbc.sql("""
					INSERT INTO %s.oauth_clients
					    (client_id, tenant_id, client_identifier, display_name, client_type,
					     authentication_method)
					VALUES (:clientId, '00000000-0000-0000-0000-000000000001',
					        'upgrade-client', 'Upgrade Client', 'public', 'none')
					""".formatted(schema)).param("clientId", CLIENT_ID).update();

			Flyway current = flyway(schema, null);
			assertThat(current.migrate().migrationsExecuted).isOne();
			assertThat(jdbc.sql("""
					SELECT refresh_tokens_enabled::text || '|' || refresh_token_ttl_seconds
					FROM %s.oauth_clients
					WHERE client_id = :clientId
					""".formatted(schema)).param("clientId", CLIENT_ID).query(String.class).single())
				.isEqualTo("false|3600");
			assertThat(current.validateWithResult().validationSuccessful).isTrue();
			assertThat(migrationCount(jdbc, schema)).isEqualTo(13);
			assertThat(current.migrate().migrationsExecuted).isZero();
		}
		finally {
			jdbc.sql("DROP SCHEMA IF EXISTS " + schema + " CASCADE").update();
		}
	}

	private Flyway flyway(String schema, String target) {
		var configuration = Flyway.configure()
			.dataSource(this.dataSource)
			.locations("classpath:db/migration")
			.defaultSchema(schema)
			.schemas(schema)
			.createSchemas(true)
			.cleanDisabled(true)
			.failOnMissingLocations(true)
			.outOfOrder(false)
			.validateMigrationNaming(true)
			.validateOnMigrate(true);
		if (target != null) {
			configuration.target(target);
		}
		return configuration.load();
	}

	private static void insertHistoricalData(JdbcClient jdbc, String schema) {
		jdbc.sql(("""
				INSERT INTO %s.tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'upgrade-test', 'Upgrade Test')
				""").formatted(schema)).param("tenantId", TENANT_ID).update();
		jdbc.sql(("""
				INSERT INTO %s.users (user_id, tenant_id)
				VALUES (:userId, :tenantId)
				""").formatted(schema)).param("userId", USER_ID).param("tenantId", TENANT_ID).update();
		jdbc.sql(("""
				INSERT INTO %s.user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES
				    (:tenantId, :userId, 'email', 'Alice@example.com', 'alice@example.com')
				""").formatted(schema)).param("tenantId", TENANT_ID).param("userId", USER_ID).update();
	}

	private static int count(JdbcClient jdbc, String schema, String table) {
		return jdbc.sql("SELECT count(*) FROM " + schema + "." + table).query(Integer.class).single();
	}

	private static int migrationCount(JdbcClient jdbc, String schema) {
		String query = "SELECT count(*) FROM " + schema
				+ ".flyway_schema_history WHERE version IS NOT NULL AND success";
		return jdbc.sql(query)
			.query(Integer.class)
			.single();
	}

	private static String identifier(JdbcClient jdbc, String schema) {
		return jdbc.sql("""
				SELECT identifier_value || '|' || canonical_value
				FROM %s.user_login_identifiers
				WHERE tenant_id = :tenantId AND user_id = :userId
				""".formatted(schema))
			.param("tenantId", TENANT_ID)
			.param("userId", USER_ID)
			.query(String.class)
			.single();
	}

}
