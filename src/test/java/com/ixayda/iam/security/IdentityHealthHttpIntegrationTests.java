package com.ixayda.iam.security;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentitySigningKeyIncidents;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.SecurityAudits;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.protocol.identity-frontend-uri=https://iam.example/identity",
		"iam.browser.requests-per-second=1", "iam.browser.concurrent-requests=1", "spring.datasource.hikari.connection-timeout=500" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityHealthHttpIntegrationTests extends BrowserHttpTestSupport {

	private static final Path SIGNING = keyFile(32);
	private static final Path AUTHORIZATION = keyFile(64);
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:health-test", "internal:test", UUID.randomUUID());
	private static final JsonMapper JSON = new JsonMapper();
	@Autowired JdbcClient jdbc;
	@Autowired IdentitySigningKeys keys;
	@Autowired IdentitySigningKeyIncidents incidents;
	@Autowired IdentityUsers users;
	@Autowired SecurityAudits audits;
	@Autowired PostgreSQLContainer postgres;
	@Autowired ConfigurableApplicationContext application;
	private String probeCookie = "__Host-IAMSESSION=stale-probe-cookie";

	@DynamicPropertySource
	static void protocolKeys(DynamicPropertyRegistry registry) {
		registry.add("iam.signing.key-file", () -> SIGNING.toString()); registry.add("iam.authorization.key-file", () -> AUTHORIZATION.toString());
	}

	@BeforeEach
	void establishHealthyState() {
		AvailabilityChangeEvent.publish(this.application, LivenessState.CORRECT); AvailabilityChangeEvent.publish(this.application, ReadinessState.ACCEPTING_TRAFFIC);
		this.users.create("health" + UUID.randomUUID().toString().replace("-", "").substring(0, 12), "Health Fixture", AUDIT);
	}

	@Test
	void publicProbesReturnStatusOnlyAndCreateNoSessionsOrAuditEventsEvenAboveBrowserAdmissionBudget() throws Exception {
		long sessions = count("iam_browser_session"); long audits = count("iam_security_audit");
		for (int i = 0; i < 4; i++) {
			for (String path : IdentityHealthRequestFilter.PATHS) { probe(path, 200, "UP"); }
		}
		assertThat(count("iam_browser_session")).isEqualTo(sessions); assertThat(count("iam_security_audit")).isEqualTo(audits);
	}

	@Test
	void databaseConnectionFailureWithdrawsReadinessWithoutBreakingLivenessAndRecoversAfterRepair() throws Exception {
		await().pollInterval(Duration.ofMillis(200)).atMost(Duration.ofSeconds(4)).untilAsserted(() -> {
			var csrf = send("/api/csrf", "GET", null); assertThat(csrf.statusCode()).isEqualTo(200); this.probeCookie = cookie(csrf);
		});
		String maintenanceUrl = "jdbc:postgresql://" + this.postgres.getHost() + ":" + this.postgres.getMappedPort(5432) + "/postgres";
		try (var connection = DriverManager.getConnection(maintenanceUrl, this.postgres.getUsername(), this.postgres.getPassword()); var statement = connection.createStatement()) {
			String database = this.postgres.getDatabaseName().replace("\"", "\"\"");
			statement.execute("ALTER DATABASE \"" + database + "\" ALLOW_CONNECTIONS false");
			try {
				try (var terminate = connection.prepareStatement("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=?")) {
					terminate.setString(1, this.postgres.getDatabaseName()); terminate.execute();
				}
				probe("/livez", 200, "UP"); probe("/readyz", 503, "DOWN"); probe("/livez", 200, "UP");
			}
			finally { statement.execute("ALTER DATABASE \"" + database + "\" ALLOW_CONNECTIONS true"); }
		}
		await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> probe("/readyz", 200, "UP"));
	}

	@Test
	void corruptedPrivateMaterialIsNotReadyEvenWhileTheProcessRemainsLive() throws Exception {
		byte[] original = this.jdbc.sql("SELECT encrypted_private_key FROM iam_signing_key WHERE status='active'").query(byte[].class).single();
		this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,40,get_byte(encrypted_private_key,40) # 1) WHERE status='active'").update();
		try { probe("/readyz", 503, "DOWN"); probe("/livez", 200, "UP"); }
		finally { this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=:original WHERE status='active'").param("original", original).update(); }
		probe("/readyz", 200, "UP");
	}

	@Test
	void containmentWithdrawsReadinessUntilControlledReplacement() throws Exception {
		UUID current = this.keys.findPublicKey().orElseThrow().id(); this.incidents.compromise(current, AUDIT);
		try { probe("/readyz", 503, "DOWN"); probe("/livez", 200, "UP"); }
		finally { this.keys.recover(current, AUDIT); }
		probe("/readyz", 200, "UP");
	}

	@Test
	void auditWriteFailureIsVisibleUntilARealAuditCommitsAndProbesDoNotWriteRecoveryEvents() throws Exception {
		this.jdbc.sql("CREATE FUNCTION health_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-audit-storage-detail'; END $$").update();
		this.jdbc.sql("CREATE TRIGGER health_audit_fault BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION health_audit_fault()").update();
		try { assertThatThrownBy(() -> this.users.create("unavailable", "Unavailable", AUDIT)).isInstanceOf(RuntimeException.class); }
		finally { this.jdbc.sql("DROP TRIGGER health_audit_fault ON iam_security_audit").update(); this.jdbc.sql("DROP FUNCTION health_audit_fault()").update(); }
		long before = count("iam_security_audit"); probe("/readyz", 503, "DOWN"); probe("/livez", 200, "UP");
		assertThat(count("iam_security_audit")).isEqualTo(before);
		this.users.create("recovered", "Recovered", AUDIT); probe("/readyz", 200, "UP");
	}

	@Test
	void availabilityEventsControlTheTwoProbeGroupsIndependently() throws Exception {
		AvailabilityChangeEvent.publish(this.application, ReadinessState.REFUSING_TRAFFIC);
		try { probe("/readyz", 503, "OUT_OF_SERVICE"); probe("/livez", 200, "UP"); }
		finally { AvailabilityChangeEvent.publish(this.application, ReadinessState.ACCEPTING_TRAFFIC); }
		AvailabilityChangeEvent.publish(this.application, LivenessState.BROKEN);
		try { probe("/livez", 503, "DOWN"); probe("/readyz", 200, "UP"); }
		finally { AvailabilityChangeEvent.publish(this.application, LivenessState.CORRECT); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "POST", "PUT", "DELETE", "OPTIONS", "HEAD" })
	void probesAcceptOnlyGet(String method) throws Exception {
		for (String path : IdentityHealthRequestFilter.PATHS) {
			var response = send(path, method, null); assertThat(response.statusCode()).isEqualTo(405); assertThat(response.headers().firstValue("Allow")).contains("GET");
			assertSecurityHeaders(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "query", "body", "chunked" })
	void probesRejectQueriesAndBodies(String fault) throws Exception {
		for (String path : IdentityHealthRequestFilter.PATHS) {
			var response = send(path + (fault.equals("query") ? "?showDetails=true" : ""), "GET", fault.equals("query") ? null : fault);
			assertThat(response.statusCode()).as(response.body()).isEqualTo(400); assertSecurityHeaders(response);
		}
	}

	@Test
	void otherActuatorRoutesExposeNoStatusOrInternalDetails() throws Exception {
		for (String path : List.of("/actuator", "/actuator/health", "/actuator/health/db", "/actuator/env", "/actuator/configprops", "/actuator/metrics", "/actuator/shutdown")) {
			await().pollInterval(Duration.ofMillis(200)).atMost(Duration.ofSeconds(4)).untilAsserted(() -> {
				var response = send(path, "GET", null); assertThat(response.statusCode()).isIn(401, 403);
				assertThat(response.body()).doesNotContain("components", "diskSpace", "Hikari", "jdbc:postgresql", "spring.datasource", "_links");
			});
		}
	}

	private void probe(String path, int status, String state) throws Exception {
		var response = send(path, "GET", null); assertThat(response.statusCode()).as(path).isEqualTo(status);
		assertSecurityHeaders(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		var json = JSON.readTree(response.body()); assertThat(json.propertyNames()).containsExactly("status"); assertThat(json.path("status").asText()).isEqualTo(state);
	}

	private HttpResponse<String> send(String path, String method, String body) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20)).header("Cookie", this.probeCookie);
		var publisher = body == null ? HttpRequest.BodyPublishers.noBody() : body.equals("chunked")
				? HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(new byte[] { 1 })) : HttpRequest.BodyPublishers.ofString(body);
		try (var http = client()) { return http.send(request.method(method, publisher).build(), HttpResponse.BodyHandlers.ofString()); }
	}

	private long count(String table) { return this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single(); }

	private static Path keyFile(int length) {
		try {
			byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes); Path file = Files.createTempFile("iam-health-", ".key");
			Files.write(file, bytes); file.toFile().deleteOnExit(); return file;
		}
		catch (java.io.IOException ex) { throw new java.io.UncheckedIOException(ex); }
	}
}
