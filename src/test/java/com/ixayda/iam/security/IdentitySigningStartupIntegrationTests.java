package com.ixayda.iam.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.service.IdentityAdministratorRecoveries;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentitySigningKeys;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class IdentitySigningStartupIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final Path OTHER_KEY_FILE = keyFile();
	@Autowired private PostgreSQLContainer postgres;
	@Autowired private JdbcClient jdbc;
	@TempDir private Path directory;
	private String schema;

	@BeforeEach
	void createSchema() {
		this.schema = "signing_startup_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + this.schema).update();
	}

	@AfterEach
	void dropSchema() { this.jdbc.sql("DROP SCHEMA " + this.schema + " CASCADE").update(); }

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void migratesAndCommitsTheKeyBeforeTheWebServerStartsThenKeepsItAcrossRestart(boolean lazyInitialization, CapturedOutput output) {
		var observed = new AtomicReference<UUID>();
		ApplicationListener<WebServerInitializedEvent> listener = event -> {
			var keys = event.getApplicationContext().getBean(IdentitySigningKeys.class);
			observed.set(keys.findPublicKey().orElseThrow().id());
		};
		UUID id;
		String privateEncoding;
		try (var application = start(WebApplicationType.SERVLET, KEY_FILE.toString(), listener, lazyInitialization)) {
			var material = application.getBean(IdentitySigningKeys.class).signingMaterial();
			id = material.key().id();
			privateEncoding = java.util.Base64.getEncoder().encodeToString(material.privateKey().getEncoded());
			assertThat(observed).hasValue(id);
		}
		var before = snapshot();
		try (var application = start(WebApplicationType.SERVLET, KEY_FILE.toString(), listener, lazyInitialization)) {
			assertThat(application.getBean(IdentitySigningKeys.class).findPublicKey().orElseThrow().id()).isEqualTo(id);
		}
		assertThat(snapshot()).isEqualTo(before);
		assertThat(output).doesNotContain(privateEncoding);
		assertThat(count("iam_security_audit")).isEqualTo(1);
	}

	@ParameterizedTest(name = "{0}, lazy initialization = {1}")
	@MethodSource("invalidSigningConfigurations")
	void invalidPersistedSigningStatePreventsTheWebServerFromStarting(String fault, boolean lazyInitialization) throws IOException {
		try (var application = start(WebApplicationType.SERVLET, KEY_FILE.toString(), null)) {
			assertThat(application.isActive()).isTrue();
		}
		String configuredKey = protectionFile(fault);
		if (fault.equals("corrupt")) {
			this.jdbc.sql("UPDATE " + this.schema + ".iam_signing_key SET encrypted_private_key = set_byte(encrypted_private_key,40,get_byte(encrypted_private_key,40) # 1)").update();
		}
		if (fault.equals("missing-state")) { this.jdbc.sql("TRUNCATE " + this.schema + ".iam_signing_key_state").update(); }
		var before = snapshot();
		var started = new AtomicInteger();
		ApplicationListener<WebServerInitializedEvent> listener = event -> started.incrementAndGet();
		assertThatThrownBy(() -> {
			try (var ignored = start(WebApplicationType.SERVLET, configuredKey, listener, lazyInitialization)) {
				fail("Inconsistent signing state must prevent Web startup");
			}
		}).isInstanceOf(RuntimeException.class);
		assertThat(started).hasValue(0);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void aFreshDatabaseWithoutConfigurationCanRunIdentityServicesWithoutCreatingSigningMaterial() {
		try (var application = start(WebApplicationType.SERVLET, "", null)) {
			assertThat(application.getBean(IdentitySigningKeys.class).findPublicKey()).isEmpty();
		}
		assertThat(count("iam_signing_key")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "absent", "valid", "missing-file", "invalid-length" })
	void administratorContextsStartWithoutSigningConfigurationOrInitialization(String configuration) throws IOException {
		try (var application = start(WebApplicationType.NONE, protectionFile(configuration), null)) {
			assertThat(application.getBean(IdentityAdministrators.class).candidateId()).isEmpty();
			assertThat(application.getBean(IdentityAdministratorRecoveries.class)).isNotNull();
		}
		assertThat(count("iam_signing_key")).isZero();
		assertThat(count("iam_security_audit")).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "absent", "wrong", "missing-file", "invalid-length" })
	void administratorContextsPreserveExistingSigningStateWithoutUsingTheProtectionFile(String configuration) throws IOException {
		try (var application = start(WebApplicationType.SERVLET, KEY_FILE.toString(), null)) {
			assertThat(application.isActive()).isTrue();
		}
		var before = snapshot();
		try (var application = start(WebApplicationType.NONE, protectionFile(configuration), null)) {
			assertThat(application.getBean(IdentityAdministrators.class).candidateId()).isEmpty();
			assertThat(application.getBean(IdentityAdministratorRecoveries.class)).isNotNull();
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void upgradingTheExistingSchemaPreservesIdentityAndAuditDataWithoutCreatingKeys() throws Exception {
		Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(this.schema).defaultSchema(this.schema).target("20").load().migrate();
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			connection.setSchema(this.schema);
			var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
			UUID id = UUID.randomUUID();
			previous.sql("INSERT INTO iam_user (id, username, display_name) VALUES (:id, 'alice', 'Alice')").param("id", id).update();
			previous.sql("INSERT INTO iam_security_audit (id,actor,source,correlation_id,target_user_id,action,outcome) VALUES (:id,'system:fixture','internal:test',:correlation,:user,'user_created','success')")
					.param("id", UUID.randomUUID()).param("correlation", UUID.randomUUID()).param("user", id).update();
			var before = List.of("iam_user", "iam_security_audit", "iam_admin_bootstrap").stream()
					.map(table -> previous.sql("SELECT row_to_json(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
			try (var ignored = start(WebApplicationType.NONE, KEY_FILE.toString(), null)) {
				var after = List.of("iam_user", "iam_security_audit", "iam_admin_bootstrap").stream()
						.map(table -> previous.sql("SELECT row_to_json(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				assertThat(after).isEqualTo(before);
				assertThat(count("iam_signing_key")).isZero();
			}
		}
	}

	private ConfigurableApplicationContext start(WebApplicationType type, String keyFile, ApplicationListener<WebServerInitializedEvent> listener) {
		return start(type, keyFile, listener, false);
	}

	private ConfigurableApplicationContext start(WebApplicationType type, String keyFile, ApplicationListener<WebServerInitializedEvent> listener, boolean lazyInitialization) {
		var builder = new SpringApplicationBuilder(IamApplication.class).web(type).lazyInitialization(lazyInitialization).properties(Map.ofEntries(
				Map.entry("spring.datasource.url", this.postgres.getJdbcUrl()), Map.entry("spring.datasource.username", this.postgres.getUsername()),
				Map.entry("spring.datasource.password", this.postgres.getPassword()), Map.entry("spring.datasource.hikari.schema", this.schema),
				Map.entry("spring.flyway.schemas", this.schema), Map.entry("spring.flyway.default-schema", this.schema),
				Map.entry("iam.signing.key-file", keyFile), Map.entry("server.port", "0"), Map.entry("spring.main.banner-mode", "off")));
		if (listener != null) { builder.listeners(listener); }
		return builder.run();
	}

	private String protectionFile(String configuration) throws IOException {
		return switch (configuration) {
			case "absent" -> "";
			case "valid", "corrupt", "missing-state" -> KEY_FILE.toString();
			case "wrong" -> OTHER_KEY_FILE.toString();
			case "missing-file" -> this.directory.resolve("missing.key").toString();
			case "invalid-length" -> Files.write(this.directory.resolve("invalid.key"), new byte[31]).toString();
			default -> throw new IllegalArgumentException("Unknown signing configuration: " + configuration);
		};
	}

	private static Stream<Arguments> invalidSigningConfigurations() {
		return Stream.of("absent", "wrong", "missing-file", "invalid-length", "corrupt", "missing-state")
				.flatMap(fault -> Stream.of(false, true).map(lazy -> Arguments.of(fault, lazy)));
	}

	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + this.schema + "." + table).query(Long.class).single(); }

	private List<List<String>> snapshot() {
		return List.of("iam_signing_key", "iam_signing_key_state", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT row_to_json(r)::text FROM " + this.schema + "." + table + " r ORDER BY 1").query(String.class).list()).toList();
	}

	private static Path keyFile() {
		try {
			byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
			Path file = Files.createTempFile("iam-signing-startup-", ".key"); Files.write(file, bytes); file.toFile().deleteOnExit(); return file;
		}
		catch (java.io.IOException ex) { throw new java.io.UncheckedIOException(ex); }
	}

}
