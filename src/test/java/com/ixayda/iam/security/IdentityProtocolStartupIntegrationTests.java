package com.ixayda.iam.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.service.IdentityAdministrators;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityProtocolStartupIntegrationTests {

	@Autowired private PostgreSQLContainer postgres;
	@Autowired private JdbcClient jdbc;
	@TempDir private Path directory;
	private String schema;
	private Path signing;
	private Path authorization;

	@BeforeEach
	void prepareIsolatedConfiguration() throws Exception {
		this.schema = "protocol_startup_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + this.schema).update();
		this.signing = keyFile("signing", 32); this.authorization = keyFile("authorization", 64);
	}

	@AfterEach
	void dropIsolatedSchema() { this.jdbc.sql("DROP SCHEMA " + this.schema + " CASCADE").update(); }

	@ParameterizedTest
	@ValueSource(strings = { "", "http://iam.example", "https://operator:secret@iam.example", "https://iam.example?query=private", "https://iam.example#private", "https://iam.example:0", "https://iam.example:65536", "https://iam.example:",
			"https://iam.example/tenant", "https://iam.example/tenant/" })
	void invalidIssuerStopsWebStartupEvenWithLazyInitialization(String issuer) {
		var started = new AtomicInteger();
		assertThatThrownBy(() -> {
			try (var ignored = start(WebApplicationType.SERVLET, issuer, this.signing.toString(), this.authorization.toString(), true, started)) {
				fail("An invalid issuer must not admit requests");
			}
		}).isInstanceOf(RuntimeException.class).hasRootCauseInstanceOf(IllegalArgumentException.class)
				.hasRootCauseMessage("An explicit HTTPS issuer at the root path is required");
		assertThat(started).hasValue(0);
	}

	@ParameterizedTest
	@ValueSource(strings = { "signing", "authorization" })
	void activatingProtocolRequiresBothProtectionFilesBeforeTheWebServerStarts(String missing) {
		var started = new AtomicInteger();
		assertThatThrownBy(() -> {
			try (var ignored = start(WebApplicationType.SERVLET, "https://iam.example", missing.equals("signing") ? "" : this.signing.toString(),
					missing.equals("authorization") ? "" : this.authorization.toString(), true, started)) {
				fail("Protocol signing and persistence must both be configured");
			}
		}).isInstanceOf(RuntimeException.class);
		assertThat(started).hasValue(0);
	}

	@Test
	void validConfigurationStartsProtocolAndInvalidWebSettingsDoNotBlockOfflineAdministration() {
		var started = new AtomicInteger();
		try (var application = start(WebApplicationType.SERVLET, "https://iam.example", this.signing.toString(), this.authorization.toString(), true, started)) {
			assertThat(application.getBean("protocolSecurity")).isNotNull(); assertThat(started).hasValue(1);
			assertThat(application.getBeansOfType(IdentityAuthorizationEndpoint.class)).isEmpty();
		}
		try (var application = start(WebApplicationType.NONE, "invalid-web-issuer", "", "", true, new AtomicInteger())) {
			assertThat(application.getBeansOfType(IdentityProtocolConfiguration.class)).isEmpty();
			assertThat(application.getBean(IdentityAdministrators.class).candidateId()).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "http://iam.example/identity/authorize", "https://other.example/identity/authorize", "https://iam.example:9443/identity/authorize",
			"https://iam.example/identity/authorize?redirect=untrusted", "https://iam.example/identity/authorize#private", "https://iam.example/identity/%0Aauthorize" })
	void invalidIdentityFrontendStopsStartupBeforeRequestsAreAdmitted(String frontend) {
		var started = new AtomicInteger();
		assertThatThrownBy(() -> {
			try (var ignored = start(WebApplicationType.SERVLET, "https://iam.example", this.signing.toString(), this.authorization.toString(), true, started, frontend)) {
				fail("An invalid identity frontend must not admit requests");
			}
		}).isInstanceOf(RuntimeException.class);
		assertThat(started).hasValue(0);
	}

	@Test
	void sameOriginIdentityFrontendActivatesTheBoundAuthorizationWorkflow() {
		var started = new AtomicInteger();
		try (var application = start(WebApplicationType.SERVLET, "https://iam.example", this.signing.toString(), this.authorization.toString(), true, started,
				"https://iam.example:443/identity/authorize")) {
			assertThat(application.getBean(IdentityAuthorizationEndpoint.class)).isNotNull(); assertThat(started).hasValue(1);
		}
	}

	private ConfigurableApplicationContext start(WebApplicationType type, String issuer, String signing, String authorization,
			boolean lazy, AtomicInteger started) {
		return start(type, issuer, signing, authorization, lazy, started, null);
	}

	private ConfigurableApplicationContext start(WebApplicationType type, String issuer, String signing, String authorization,
			boolean lazy, AtomicInteger started, String frontend) {
		ApplicationListener<WebServerInitializedEvent> listener = event -> started.incrementAndGet();
		var properties = new java.util.HashMap<String, Object>(Map.ofEntries(
				Map.entry("spring.datasource.url", this.postgres.getJdbcUrl()), Map.entry("spring.datasource.username", this.postgres.getUsername()),
				Map.entry("spring.datasource.password", this.postgres.getPassword()), Map.entry("spring.datasource.hikari.schema", this.schema),
				Map.entry("spring.flyway.schemas", this.schema), Map.entry("spring.flyway.default-schema", this.schema),
				Map.entry("iam.protocol.issuer", issuer), Map.entry("iam.signing.key-file", signing), Map.entry("iam.authorization.key-file", authorization),
				Map.entry("server.port", "0"), Map.entry("spring.main.banner-mode", "off")));
		if (frontend != null) { properties.put("iam.protocol.identity-frontend-uri", frontend); }
		return new SpringApplicationBuilder(IamApplication.class).web(type).lazyInitialization(lazy).listeners(listener).properties(properties).run();
	}

	private Path keyFile(String name, int length) throws Exception {
		byte[] value = new byte[length]; new SecureRandom().nextBytes(value);
		Path path = Files.write(this.directory.resolve(name + ".key"), value); java.util.Arrays.fill(value, (byte) 0); return path;
	}

}
