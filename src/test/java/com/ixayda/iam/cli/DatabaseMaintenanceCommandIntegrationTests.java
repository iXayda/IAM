package com.ixayda.iam.cli;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorRecoveries;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.*;

@ResourceLock("java.lang.System.properties")
class DatabaseMaintenanceCommandIntegrationTests extends BrowserHttpTestSupport {

	private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer(
			"postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");
	private static final String PASSWORD = "saffron village ripple lantern 936";
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:installation-test", "internal:test", UUID.randomUUID());
	private static final JsonMapper JSON = new JsonMapper();
	@TempDir Path directory;
	private String database;
	private String owner;
	private String runtime;
	private String databasePassword;
	private String url;
	private JdbcClient maintenance;
	private Path signingKey;
	private Path authorizationKey;
	private final AtomicInteger startedServers = new AtomicInteger();

	@BeforeAll
	static void startDatabase() {
		POSTGRES.start();
		POSTGRES.copyFileToContainer(MountableFile.forHostPath(Path.of("deploy/postgresql/grant-runtime.sql")), "/tmp/grant-runtime.sql");
	}

	@AfterAll
	static void stopDatabase() { POSTGRES.stop(); }

	@BeforeEach
	void createIndependentOwnerAndRuntimeIdentities() throws Exception {
		String suffix = UUID.randomUUID().toString().replace("-", "");
		this.database = "installation_" + suffix; this.owner = "owner_" + suffix; this.runtime = "runtime_" + suffix;
		this.databasePassword = UUID.randomUUID().toString();
		try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()); var statement = connection.createStatement()) {
			statement.execute("CREATE ROLE " + this.owner + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + this.databasePassword + "'");
			statement.execute("CREATE ROLE " + this.runtime + " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + this.databasePassword + "'");
			statement.execute("CREATE DATABASE " + this.database + " OWNER " + this.owner);
		}
		this.url = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + this.database;
		this.maintenance = JdbcClient.create(new DriverManagerDataSource(this.url, this.owner, this.databasePassword));
		this.signingKey = keyFile("signing.key", 32); this.authorizationKey = keyFile("authorization.key", 64);
	}

	@AfterEach
	void removeIsolatedDatabaseAndRoles() throws Exception {
		try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()); var statement = connection.createStatement()) {
			statement.execute("DROP DATABASE " + this.database + " WITH (FORCE)");
			statement.execute("DROP ROLE " + this.runtime); statement.execute("DROP ROLE " + this.owner);
		}
	}

	@Test
	void commandMigratesWithoutOpeningAListenerOrInitializingSigningAndThenInitializesIdempotently() {
		runCommand("migrate");
		assertThat(count("flyway_schema_history")).isGreaterThanOrEqualTo(40);
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_administrator")).isZero();
		assertThat(count("iam_security_audit")).isZero();
		runCommand("initialize-signing-key");
		String initial = this.maintenance.sql("SELECT initial_key_id::text FROM iam_signing_key_state").query(String.class).single();
		runCommand("initialize-signing-key");
		assertThat(count("iam_signing_key")).isEqualTo(1); assertThat(count("iam_security_audit")).isEqualTo(1);
		assertThat(this.maintenance.sql("SELECT actor FROM iam_security_audit").query(String.class).single()).isEqualTo("system:installation");
		assertThat(this.maintenance.sql("SELECT initial_key_id::text FROM iam_signing_key_state").query(String.class).single()).isEqualTo(initial);
	}

	@Test
	void migrationRequiresOwnerOnBothBusinessAndFlywayConnectionsBeforeCreatingHistory() {
		this.maintenance.sql("GRANT CREATE ON SCHEMA public TO " + this.runtime).update();
		for (boolean nonOwnerFlyway : List.of(true, false)) {
			var properties = installationProperties();
			properties.put("spring.datasource.username", nonOwnerFlyway ? this.owner : this.runtime);
			properties.put("spring.flyway.url", this.url);
			properties.put("spring.flyway.user", nonOwnerFlyway ? this.runtime : this.owner);
			properties.put("spring.flyway.password", this.databasePassword);
			withSystemProperties(properties, () -> assertThatThrownBy(() -> IamApplication.main(new String[] { "migrate" }))
					.hasStackTraceContaining("database owner"));
			assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'").query(Long.class).single()).isZero();
		}
	}

	@Test
	void migrationRejectsDelegatedOwnerOnTheActualFlywayConnection() throws Exception {
		adminSql("GRANT " + this.owner + " TO " + this.runtime);
		withSystemProperties(Map.of("spring.flyway.user", this.runtime, "spring.flyway.password", this.databasePassword,
				"spring.flyway.url", this.url + "?options=-c%20role%3D" + this.owner), () ->
				assertThatThrownBy(() -> runCommand("migrate")).hasStackTraceContaining("database owner"));
		assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "spring.flyway.init-sqls[0]", "spring.datasource.hikari.connection-init-sql" })
	void migrationRejectsConnectionInitializationSqlBeforeItCanWrite(String property) {
		this.maintenance.sql("CREATE TABLE init_marker (id integer)").update();
		this.maintenance.sql("GRANT INSERT ON init_marker TO " + this.runtime).update();
		var properties = installationProperties();
		properties.put(property, "INSERT INTO init_marker VALUES (1)");
		properties.put("spring.flyway.url", this.url);
		properties.put("spring.flyway.user", this.runtime);
		properties.put("spring.flyway.password", this.databasePassword);
		withSystemProperties(properties, () -> assertThatThrownBy(() -> IamApplication.main(new String[] { "migrate" }))
				.hasStackTraceContaining("connection initialization SQL"));
		assertThat(count("init_marker")).isZero();
		assertThat(this.maintenance.sql("SELECT to_regclass('flyway_schema_history') IS NULL").query(Boolean.class).single()).isTrue();
	}

	@Test
	void maintenanceRequiresOwnerEvenWithReadableHistoryAndWritableBusinessTables() {
		runCommand("migrate");
		this.maintenance.sql("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + this.runtime).update();
		var properties = installationProperties();
		properties.put("spring.datasource.username", this.runtime);
		properties.put("spring.datasource.hikari.maximum-pool-size", 1);
		withSystemProperties(properties, () -> assertThatThrownBy(() -> IamApplication.main(new String[] { "initialize-signing-key" }))
				.hasStackTraceContaining("database owner"));
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
	}

	@Test
	void authorizationKeyInitializationIsExplicitAndIdempotent() {
		runCommand("migrate");
		assertThat(this.maintenance.sql("SELECT key_id FROM iam_authorization_protection").query(String.class).optional()).isEmpty();
		runCommand("initialize-authorization-key");
		String keyId = this.maintenance.sql("SELECT key_id FROM iam_authorization_protection").query(String.class).single();
		runCommand("initialize-authorization-key");
		assertThat(this.maintenance.sql("SELECT key_id FROM iam_authorization_protection").query(String.class).single()).isEqualTo(keyId);
		assertThat(count("iam_authorization_protection")).isEqualTo(1);
		assertThat(this.startedServers).hasValue(0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "initialize-signing-key", "initialize-authorization-key", "preview-protocol-cleanup", "cleanup-protocol-state", "bootstrap-admin", "recover-admin", "recover-admin-credentials", "rotate-signing-key", "compromise-signing-key", "recover-signing-key", "quarantine-restore", "recover-restored-admin" })
	void everyMaintenanceStartupRefusesAnEmptySchemaWithMigrationExplicitlyEnabled(String command) {
		withSystemProperties(installationProperties(), () -> withSystemProperties(Map.of("spring.flyway.enabled", "true"), () ->
				assertThatThrownBy(() -> { try (var ignored = MaintenanceApplication.start(IamApplication.class, command)) { fail("Empty schema must be rejected"); } })
						.isInstanceOf(RuntimeException.class)));
		assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'").query(Long.class).single()).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void migrationCommandFailsWhenFlywayIsDisabledAndCannotBeChangedIntoAWebCommand() {
		withSystemProperties(Map.of("spring.flyway.enabled", "false"), () -> assertThatThrownBy(() -> runCommand("migrate")).isInstanceOf(RuntimeException.class));
		assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'").query(Long.class).single()).isZero();
		withSystemProperties(Map.of("spring.main.web-application-type", "servlet"), () ->
				assertThatThrownBy(() -> runCommand("migrate")).isInstanceOf(IllegalStateException.class).hasMessageContaining("non-Web"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "migrate", "initialize-signing-key", "initialize-authorization-key", "preview-protocol-cleanup", "cleanup-protocol-state" })
	void maintenanceDispatchRejectsAdditionalArguments(String command) {
		assertThatIllegalArgumentException().isThrownBy(() -> IamApplication.main(new String[] { command, "--server.port=0" }));
	}

	@ParameterizedTest
	@ValueSource(strings = { "initialize-signing-key", "initialize-authorization-key", "preview-protocol-cleanup", "cleanup-protocol-state" })
	void maintenanceRequiresAMigratedSchemaAndNeverRunsFlyway(String command) {
		withSystemProperties(Map.of("spring.flyway.enabled", "true"), () -> assertThatThrownBy(() -> runCommand(command)).isInstanceOf(RuntimeException.class));
		assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'").query(Long.class).single()).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "initialize-signing-key", "initialize-authorization-key", "preview-protocol-cleanup", "cleanup-protocol-state" })
	void maintenanceRejectsPendingMigrationsWithoutChangingSchemaOrSecurityState(String command) {
		runCommand("migrate");
		this.maintenance.sql("DELETE FROM flyway_schema_history WHERE installed_rank=(SELECT max(installed_rank) FROM flyway_schema_history)").update();
		long history = count("flyway_schema_history");
		withSystemProperties(Map.of("spring.flyway.target", "1", "spring.flyway.ignore-migration-patterns", "*:pending"), () ->
				assertThatThrownBy(() -> runCommand(command)).isInstanceOf(RuntimeException.class));
		assertThat(count("flyway_schema_history")).isEqualTo(history);
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
		assertThat(this.startedServers).hasValue(0);
	}


	@ParameterizedTest
	@ValueSource(strings = { "quarantine-restore", "recover-restored-admin" })
	void restoreAdmissionValidatesWithItsSingleConnectionPool(String command) {
		runCommand("migrate");
		withSystemProperties(installationProperties(), () -> withSystemProperties(Map.of("spring.datasource.hikari.connection-timeout", "500"), () -> {
			try (var context = MaintenanceApplication.start(IamApplication.class, command)) {
				assertThat(context.getBean(com.zaxxer.hikari.HikariDataSource.class).getMaximumPoolSize()).isEqualTo(1);
			}
		}));
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void currentHistoryInAnotherSchemaCannotAdmitMaintenanceAgainstAnOlderBusinessSchema() {
		runCommand("migrate");
		org.flywaydb.core.Flyway.configure().dataSource(this.url, this.owner, this.databasePassword)
				.schemas("legacy").defaultSchema("legacy").target("40").load().migrate();
		assertThat(this.maintenance.sql("SELECT to_regclass('legacy.iam_authorization_protection') IS NULL").query(Boolean.class).single()).isTrue();
		long before = this.maintenance.sql("SELECT count(*) FROM legacy.flyway_schema_history").query(Long.class).single();
		withSystemProperties(Map.of("spring.datasource.hikari.schema", "legacy", "spring.flyway.default-schema", "public", "spring.flyway.schemas", "public"), () ->
				assertThatThrownBy(() -> runCommand("initialize-signing-key")).isInstanceOf(IllegalStateException.class));
		assertThat(this.maintenance.sql("SELECT count(*) FROM legacy.flyway_schema_history").query(Long.class).single()).isEqualTo(before);
		assertThat(this.maintenance.sql("SELECT count(*) FROM legacy.iam_signing_key").query(Long.class).single()).isZero();
		assertThat(this.maintenance.sql("SELECT count(*) FROM legacy.iam_security_audit").query(Long.class).single()).isZero();
		assertThat(count("iam_signing_key")).isZero(); assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void emptySearchPathPrefixStillValidatesTheResolvedBusinessSchema() {
		runCommand("migrate"); this.maintenance.sql("CREATE SCHEMA prefix").update();
		this.url += "?currentSchema=prefix,public";
		withSystemProperties(Map.of("spring.datasource.hikari.maximum-pool-size", 1), () -> runCommand("initialize-signing-key"));
		assertThat(count("iam_signing_key")).isEqualTo(1);
		assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='prefix'").query(Long.class).single()).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void maintenanceRejectsBusinessRelationsShadowedOutsideTheValidatedSchema() {
		runCommand("migrate"); this.maintenance.sql("CREATE SCHEMA prefix").update();
		this.maintenance.sql("CREATE TABLE prefix.iam_admin_bootstrap (LIKE public.iam_admin_bootstrap INCLUDING ALL)").update();
		this.url += "?currentSchema=prefix,public";
		withSystemProperties(Map.of("spring.flyway.default-schema", "public"), () ->
				assertThatThrownBy(() -> runCommand("initialize-signing-key")).isInstanceOf(IllegalStateException.class));
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
	}

	@Test
	void signingInitializationRejectsChangedMigrationChecksumsWithoutMutatingSecurityState() {
		runCommand("migrate");
		this.maintenance.sql("UPDATE flyway_schema_history SET checksum=checksum+1 WHERE installed_rank=(SELECT min(installed_rank) FROM flyway_schema_history)").update();
		long history = count("flyway_schema_history");
		assertThatThrownBy(() -> runCommand("initialize-signing-key")).isInstanceOf(RuntimeException.class);
		assertThat(count("flyway_schema_history")).isEqualTo(history);
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "initialize-signing-key", "initialize-authorization-key", "preview-protocol-cleanup", "cleanup-protocol-state" })
	void maintenanceRejectsFutureSchemaEvenWhenFlywayIgnoresFutureMigrations(String command) {
		runCommand("migrate");
		this.maintenance.sql("""
				INSERT INTO flyway_schema_history(installed_rank,version,description,type,script,checksum,installed_by,execution_time,success)
				SELECT max(installed_rank)+1,'9999','future schema','SQL','V9999__future_schema.sql',0,current_user,0,true FROM flyway_schema_history
				""").update();
		long history = count("flyway_schema_history");
		withSystemProperties(Map.of("spring.flyway.ignore-migration-patterns", "*:future"), () ->
				assertThatThrownBy(() -> runCommand(command)).isInstanceOf(RuntimeException.class));
		assertThat(count("flyway_schema_history")).isEqualTo(history);
		assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
		assertThat(this.startedServers).hasValue(0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_authorization_protection.key_id", "iam_signing_key.public_key", "iam_administrator.user_id", "iam_signing_key_state.active_key_id", "iam_admin_bootstrap.completed_at", "iam_restore_state.current_restore_id", "iam_restore_administrator.completed_at" })
	void runtimeChecksProtectedColumnsOnResolvedRelationsBehindTheFirstSearchPathSchema(String column) throws Exception {
		runCommand("migrate"); runCommand("initialize-signing-key"); runCommand("initialize-authorization-key"); applyGrants("public");
		this.maintenance.sql("CREATE SCHEMA prefix").update();
		this.maintenance.sql("GRANT USAGE ON SCHEMA prefix TO " + this.runtime).update();
		String[] target = column.split("\\.");
		this.maintenance.sql("GRANT UPDATE(" + target[1] + ") ON public." + target[0] + " TO " + this.runtime).update();
		withSystemProperties(Map.of("spring.datasource.hikari.connection-init-sql", "SET search_path TO prefix,public"), () ->
				assertThatThrownBy(() -> { try (var ignored = start(true)) { fail("Unsafe privileges must prevent startup"); } })
						.hasRootCauseMessage("IAM runtime database identity has maintenance capabilities"));
		assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void runtimeDoesNotConfuseUnresolvedDecoyTableWithTheBusinessRelation() throws Exception {
		runCommand("migrate"); runCommand("initialize-signing-key"); runCommand("initialize-authorization-key"); applyGrants("public");
		this.maintenance.sql("CREATE SCHEMA prefix").update();
		this.maintenance.sql("GRANT USAGE ON SCHEMA prefix TO " + this.runtime).update();
		this.maintenance.sql("CREATE TABLE prefix.iam_signing_key(public_key text)").update();
		this.maintenance.sql("GRANT UPDATE(public_key) ON prefix.iam_signing_key TO " + this.runtime).update();
		withSystemProperties(Map.of("spring.datasource.hikari.connection-init-sql", "SET search_path TO public,prefix"), () -> {
			try (var ignored = start(true)) { assertThat(this.startedServers).hasValue(1); }
		});
	}

	@Test
	void protocolCleanupCommandsAreOfflineRepeatableAndRejectRestrictedRuntimeCredentials() throws Exception {
		runCommand("migrate"); var before = this.maintenance.sql("SELECT row_to_json(t)::text FROM iam_admin_bootstrap t").query(String.class).list();
		runCommand("preview-protocol-cleanup"); runCommand("cleanup-protocol-state"); runCommand("cleanup-protocol-state");
		assertThat(this.maintenance.sql("SELECT row_to_json(t)::text FROM iam_admin_bootstrap t").query(String.class).list()).isEqualTo(before);
		assertThat(this.startedServers).hasValue(0); assertThat(count("iam_security_audit")).isZero();
		applyGrants("public");
		for (String command : List.of("preview-protocol-cleanup", "cleanup-protocol-state")) {
			var restricted = installationProperties(); restricted.put("spring.datasource.username", this.runtime); restricted.put("spring.flyway.enabled", "false");
			withSystemProperties(restricted, () ->
					assertThatIllegalStateException().isThrownBy(() -> IamApplication.main(new String[] { command })).withMessageContaining("database owner"));
		}
		withSystemProperties(Map.of("iam.protocol-cleanup.seconds", "0"), () ->
				assertThatIllegalArgumentException().isThrownBy(() -> runCommand("cleanup-protocol-state")));
		withSystemProperties(Map.of("spring.main.web-application-type", "servlet"), () ->
				assertThatIllegalStateException().isThrownBy(() -> runCommand("cleanup-protocol-state")).withMessageContaining("non-Web"));
	}

	@Test
	void runtimeCannotAlterAuditsBootstrapSigningOrSchemaAndRepeatedGrantsRemoveStaleColumnPermissions() throws Exception {
		runCommand("migrate"); runCommand("initialize-signing-key"); runCommand("initialize-authorization-key"); applyGrants("public");
		this.maintenance.sql("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO " + this.runtime).update();
		this.maintenance.sql("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO " + this.runtime).update();
		this.maintenance.sql("GRANT UPDATE(actor) ON iam_security_audit TO " + this.runtime).update();
		this.maintenance.sql("GRANT UPDATE(active_key_id) ON iam_signing_key_state TO PUBLIC").update();
		applyGrants("public"); applyGrants("public");
		try (var connection = DriverManager.getConnection(this.url, this.runtime, this.databasePassword)) {
			assertThat(connection.getMetaData().getUserName()).isEqualTo(this.runtime);
			for (String sql : List.of(
					"UPDATE iam_security_audit SET actor=actor", "DELETE FROM iam_security_audit", "TRUNCATE iam_security_audit",
					"UPDATE iam_signing_key SET public_key=public_key", "DELETE FROM iam_signing_key",
					"UPDATE iam_signing_key_state SET active_key_id=active_key_id", "UPDATE iam_signing_key_state SET revision=revision",
					"DELETE FROM iam_signing_key_state", "INSERT INTO iam_signing_key_state(singleton) VALUES (1)",
					"INSERT INTO iam_administrator(user_id) VALUES (gen_random_uuid())", "DELETE FROM iam_administrator",
					"UPDATE iam_admin_bootstrap SET completed_at=completed_at", "UPDATE iam_admin_bootstrap SET candidate_user_id=candidate_user_id",
					"UPDATE iam_admin_bootstrap SET restore_closed=false", "UPDATE iam_restore_state SET current_restore_id=NULL",
					"DELETE FROM iam_restore", "TRUNCATE iam_restore", "UPDATE iam_restore SET archive_sha256=archive_sha256",
					"INSERT INTO iam_restore_administrator(restore_id,user_id,factor_id) VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid())",
					"UPDATE iam_restore_administrator SET completed_at=clock_timestamp()", "DELETE FROM iam_restore_administrator", "TRUNCATE iam_restore_administrator",
					"UPDATE iam_authorization_protection SET key_id=key_id", "DELETE FROM iam_authorization_protection",
					"SELECT * FROM iam_administrator_recovery", "SELECT * FROM flyway_schema_history",
					"CREATE TABLE runtime_ddl(id int)", "CREATE TEMP TABLE runtime_temp(id int)", "CREATE SCHEMA runtime_schema",
					"ALTER TABLE iam_user DISABLE TRIGGER ALL", "SET ROLE " + this.owner)) {
				assertThatThrownBy(() -> { try (var statement = connection.createStatement()) { statement.execute(sql); } })
						.as(sql).isInstanceOf(java.sql.SQLException.class).extracting("SQLState").isEqualTo("42501");
			}
			connection.setAutoCommit(false);
			try (var statement = connection.createStatement()) {
				statement.executeQuery("SELECT * FROM iam_signing_key_state FOR SHARE");
				statement.executeQuery("SELECT * FROM iam_admin_bootstrap FOR UPDATE");
				assertThat(statement.executeUpdate("UPDATE iam_admin_bootstrap SET revision=revision+1")).isEqualTo(1);
			}
			connection.rollback();
		}
		this.maintenance.sql("CREATE TABLE future_table(id int)").update();
		assertThat(this.maintenance.sql("SELECT has_table_privilege(:role,'future_table','SELECT,INSERT,UPDATE,DELETE')").param("role", this.runtime).query(Boolean.class).single()).isFalse();
		this.maintenance.sql("CREATE FUNCTION future_function() RETURNS int LANGUAGE sql AS 'SELECT 1'").update();
		assertThat(this.maintenance.sql("SELECT has_function_privilege(:role,'future_function()','EXECUTE')").param("role", this.runtime).query(Boolean.class).single()).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "column-audit", "public-audit", "signing-state", "bootstrap", "restore-state", "restore-evidence", "restore-administrator", "owner", "membership" })
	void runtimeProfileRejectsMaintenanceCredentialsAndPrivilegeDriftBeforeListening(String fault) throws Exception {
		runCommand("migrate"); runCommand("initialize-signing-key"); runCommand("initialize-authorization-key"); applyGrants("public");
		switch (fault) {
			case "column-audit" -> this.maintenance.sql("GRANT UPDATE(actor) ON iam_security_audit TO " + this.runtime).update();
			case "public-audit" -> this.maintenance.sql("GRANT DELETE ON iam_security_audit TO PUBLIC").update();
			case "signing-state" -> this.maintenance.sql("GRANT UPDATE(active_key_id) ON iam_signing_key_state TO " + this.runtime).update();
			case "bootstrap" -> this.maintenance.sql("GRANT UPDATE(completed_at) ON iam_admin_bootstrap TO " + this.runtime).update();
			case "restore-state" -> this.maintenance.sql("GRANT UPDATE(current_restore_id) ON iam_restore_state TO " + this.runtime).update();
			case "restore-evidence" -> this.maintenance.sql("GRANT DELETE ON iam_restore TO PUBLIC").update();
			case "restore-administrator" -> this.maintenance.sql("GRANT UPDATE(completed_at) ON iam_restore_administrator TO " + this.runtime).update();
			case "membership" -> adminSql("GRANT " + this.owner + " TO " + this.runtime + " WITH INHERIT FALSE, SET TRUE");
		}
		Runnable attempt = () -> assertThatThrownBy(() -> { try (var ignored = start(true)) { fail("Unsafe identity must prevent startup"); } })
				.hasRootCauseInstanceOf(IllegalStateException.class).hasRootCauseMessage("IAM runtime database identity has maintenance capabilities");
		if (fault.equals("owner")) { withSystemProperties(Map.of("spring.datasource.username", this.owner), attempt); } else { attempt.run(); }
		assertThat(this.startedServers).hasValue(0);
	}

	@Test
	void webLauncherWithoutAProfileRefusesOwnerAndLeavesDatabasesUntouched() {
		var properties = installationProperties();
		properties.put("server.port", 0);
		withSystemProperties(properties, () -> {
			String[] overrides = { "--iam.database.restricted-runtime=false", "--spring.flyway.enabled=true" };
			assertThatThrownBy(() -> IamApplication.main(overrides)).isInstanceOf(RuntimeException.class);
			assertThat(this.maintenance.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'")
					.query(Long.class).single()).isZero();

			runCommand("migrate");
			assertThatThrownBy(() -> IamApplication.main(overrides)).hasRootCauseInstanceOf(IllegalStateException.class)
					.hasRootCauseMessage("IAM runtime database identity has maintenance capabilities");
			assertThat(count("iam_signing_key")).isZero();
			assertThat(count("iam_security_audit")).isZero();
		});
	}

	@Test
	void restrictedRuntimeCannotInitializeMissingSigningMaterialOrOpenAListener() throws Exception {
		runCommand("migrate"); applyGrants("public");
		assertThatThrownBy(() -> { try (var ignored = start(true)) { fail("Runtime must not initialize signing identity"); } }).isInstanceOf(RuntimeException.class);
		assertThat(this.startedServers).hasValue(0); assertThat(count("iam_signing_key")).isZero(); assertThat(count("iam_security_audit")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "owner", "membership", "createdb", "inherit", "schema-create", "missing-table" })
	void grantScriptRejectsUnsafeRolesAndIncompleteSchemasAtomically(String fault) throws Exception {
		runCommand("migrate");
		String role = this.runtime;
		switch (fault) {
			case "owner" -> role = this.owner;
			case "membership" -> adminSql("GRANT " + this.owner + " TO " + this.runtime + " WITH INHERIT FALSE, SET TRUE");
			case "createdb" -> alterRole("CREATEDB");
			case "inherit" -> alterRole("INHERIT");
			case "schema-create" -> { this.maintenance.sql("CREATE SCHEMA unrelated").update(); this.maintenance.sql("GRANT CREATE ON SCHEMA unrelated TO PUBLIC").update(); }
			case "missing-table" -> this.maintenance.sql("ALTER TABLE iam_resource_credential RENAME TO missing_resource_credential").update();
		}
		var result = grantResult("public", role); assertThat(result.getExitCode()).as(result.getStderr()).isNotZero();
		assertThat(this.maintenance.sql("SELECT has_table_privilege(:role,'iam_security_audit','SELECT')").param("role", this.runtime).query(Boolean.class).single()).isFalse();
		assertThat(this.maintenance.sql("SELECT has_database_privilege(:role,current_database(),'TEMPORARY')").param("role", this.runtime).query(Boolean.class).single()).isTrue();
	}

	@Test
	void quotedPsqlIdentifiersWorkWithAnExplicitSchema() throws Exception {
		String schema = "IAM-\"schema";
		this.maintenance.sql("CREATE SCHEMA \"IAM-\"\"schema\"").update();
		var properties = installationProperties(); properties.put("spring.datasource.hikari.schema", schema);
		properties.put("spring.flyway.schemas", schema); properties.put("spring.flyway.default-schema", schema);
		withSystemProperties(properties, () -> {
			IamApplication.main(new String[] { "migrate" });
			IamApplication.main(new String[] { "initialize-signing-key" });
			IamApplication.main(new String[] { "initialize-authorization-key" });
		});
		applyGrants(schema);
		assertThat(this.maintenance.sql("SELECT has_table_privilege(:role, '\"IAM-\"\"schema\".iam_security_audit', 'INSERT')").param("role", this.runtime).query(Boolean.class).single()).isTrue();
	}

	@Test
	void restrictedHttpsRuntimeLogsInIssuesAndRefreshesTokensAndAuditsSecurityChangesAcrossRestart() throws Exception {
		runCommand("migrate"); runCommand("initialize-signing-key"); runCommand("initialize-authorization-key");
		UUID userId; UUID clientId; String clientSecret;
		try (var application = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE)
				.properties(installationProperties()).run()) {
			var users = application.getBean(IdentityUsers.class);
			userId = users.create("alice", "Alice", AUDIT).id();
			var setups = application.getBean(IdentityUserSetups.class); var proof = setups.issue(userId, AUDIT);
			setups.complete(userId, proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
			var resource = application.getBean(IdentityResources.class).create("https://orders.example", "Orders", AUDIT);
			var registration = application.getBean(IdentityClients.class).create(new IdentityClientConfiguration("Orders", resource.id(),
					List.of("https://orders.example/callback"), Set.of("openid", "profile", "offline_access"), Set.of()), AUDIT);
			clientId = registration.client().id(); clientSecret = registration.secret();
		}
		applyGrants("public");
		String current = this.maintenance.sql("SELECT active_key_id::text FROM iam_signing_key_state").query(String.class).single();
		for (boolean runtimeProfile : List.of(true, false)) {
			try (var application = start(runtimeProfile); var http = client()) {
				assertThat(application.getBean(IdentitySigningKeys.class).findPublicKey().orElseThrow().id().toString()).isEqualTo(current);
				assertThat(application.getEnvironment().getProperty("spring.flyway.enabled")).isEqualTo("false");
				for (String path : List.of("/livez", "/readyz")) { assertThat(get(http, path, null).statusCode()).as(path).isEqualTo(200); }
				var csrf = get(http, "/api/csrf", null); var login = post(http, "/login", cookie(csrf), credentials("alice", PASSWORD, csrf(csrf)));
				assertThat(login.statusCode()).as(login.body()).isEqualTo(204); String session = cookie(login);
				assertThat(get(http, "/api/me", session).statusCode()).isEqualTo(200);
				String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
				var authorization = get(http, "/oauth2/authorize?response_type=code&client_id=" + clientId + "&redirect_uri="
						+ encode("https://orders.example/callback") + "&scope=openid%20profile%20offline_access&state=installation&nonce=installation-nonce&code_challenge="
						+ challenge + "&code_challenge_method=S256", session);
				assertThat(authorization.statusCode()).as(authorization.body()).isEqualTo(302);
				String rawQuery = URI.create(authorization.headers().firstValue("Location").orElseThrow()).getRawQuery();
				var query = new HashMap<String, String>(); for (String entry : rawQuery.split("&")) { String[] pair = entry.split("=", 2); query.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8)); }
				assertThat(query).containsKey("code");
				String basic = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.US_ASCII));
				var token = token(http, basic, "grant_type=authorization_code&code=" + encode(query.get("code"))
						+ "&redirect_uri=" + encode("https://orders.example/callback") + "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
				assertThat(token.path("access_token").asText()).isNotBlank();
				var refreshed = token(http, basic, "grant_type=refresh_token&refresh_token=" + encode(token.path("refresh_token").asText()));
				assertThat(refreshed.path("refresh_token").asText()).isNotEqualTo(token.path("refresh_token").asText());
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/userinfo")).header("Authorization", "Bearer " + refreshed.path("access_token").asText()).GET().build();
				var profile = http.send(request, HttpResponse.BodyHandlers.ofString()); assertThat(profile.statusCode()).as(profile.body()).isEqualTo(200);
				assertThat(JSON.readTree(profile.body()).path("sub").asText()).isEqualTo(userId.toString());
				assertThatThrownBy(() -> application.getBean(IdentityAdministratorRecoveries.class).cleanUpExpiredRecoveries()).isInstanceOf(IllegalStateException.class);
			}
		}
		try (var application = start(true)) {
			assertThat(application.getBean(IdentityUserStates.class).disable(userId, AUDIT)).isEqualTo(IdentityUserStates.Result.CHANGED);
		}
		assertThat(count("iam_security_audit")).isGreaterThan(10);
	}

	private tools.jackson.databind.JsonNode token(java.net.http.HttpClient http, String basic, String body) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/oauth2/token")).timeout(Duration.ofSeconds(20))
				.header("Content-Type", "application/x-www-form-urlencoded").header("Authorization", basic).POST(HttpRequest.BodyPublishers.ofString(body)).build();
		var response = http.send(request, HttpResponse.BodyHandlers.ofString());
		assertThat(response.statusCode()).as("Token response status").isEqualTo(200); assertSecurityHeaders(response); return JSON.readTree(response.body());
	}

	private ConfigurableApplicationContext start(boolean runtimeProfile) {
		var properties = installationProperties();
		properties.put("server.port", "0"); properties.put("server.ssl.enabled", "true"); properties.put("server.ssl.key-store", KEY_STORE.toUri().toString());
		properties.put("server.ssl.key-store-password", "test-store-password"); properties.put("iam.protocol.issuer", "https://iam.example");
		properties.put("iam.protocol.identity-frontend-uri", "https://iam.example/identity");
		properties.put("spring.datasource.username", this.runtime);
		if (runtimeProfile) { properties.put("spring.profiles.active", "runtime"); }
		else { properties.put("spring.flyway.enabled", false); }
		var application = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.SERVLET).properties(properties)
				.listeners((ApplicationListener<WebServerInitializedEvent>) event -> this.startedServers.incrementAndGet()).run();
		this.port = ((WebServerApplicationContext) application).getWebServer().getPort(); return application;
	}

	private void runCommand(String command) { withSystemProperties(installationProperties(), () -> IamApplication.main(new String[] { command })); }

	private Map<String, Object> installationProperties() {
		var properties = new HashMap<String, Object>();
		properties.put("spring.datasource.url", this.url); properties.put("spring.datasource.username", this.owner);
		properties.put("spring.datasource.password", this.databasePassword); properties.put("spring.main.banner-mode", "off");
		properties.put("iam.signing.key-file", this.signingKey.toString()); properties.put("iam.authorization.key-file", this.authorizationKey.toString());
		return properties;
	}

	private static void withSystemProperties(Map<String, ?> properties, Runnable operation) {
		var previous = new HashMap<String, String>(); properties.forEach((key, value) -> { previous.put(key, System.getProperty(key)); System.setProperty(key, value.toString()); });
		try { operation.run(); }
		finally { previous.forEach((key, value) -> { if (value == null) { System.clearProperty(key); } else { System.setProperty(key, value); } }); }
	}

	private void applyGrants(String schema) throws Exception {
		var result = grantResult(schema, this.runtime); assertThat(result.getExitCode()).as(result.getStderr()).isZero();
	}

	private org.testcontainers.containers.Container.ExecResult grantResult(String schema, String role) throws Exception {
		return POSTGRES.execInContainer("psql", "-X", "-U", this.owner, "-d", this.database, "-v", "runtime_role=" + role, "-v", "iam_schema=" + schema, "-f", "/tmp/grant-runtime.sql");
	}

	private void alterRole(String option) throws Exception {
		adminSql("ALTER ROLE " + this.runtime + " " + option);
	}

	private void adminSql(String sql) throws Exception {
		try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()); var statement = connection.createStatement()) {
			statement.execute(sql);
		}
	}

	private long count(String table) { return this.maintenance.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }

	private Path keyFile(String name, int length) throws Exception {
		byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes); return Files.write(this.directory.resolve(name), bytes);
	}
}
