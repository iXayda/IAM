package com.ixayda.iam.controller;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityResourceCredentials;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.IdentityUserSetups;

import com.jayway.jsonpath.JsonPath;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityResourceCredentialControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:resource-http-test", "internal:test", UUID.randomUUID());
	private static final JsonMapper JSON = new JsonMapper();
	private static final Path KEY_FILE = keyFile();
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityResourceCredentials credentials;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private JdbcClient jdbc;
	@Autowired private PostgreSQLContainer postgres;
	private UUID resourceId;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_browser_session,iam_security_audit,iam_password_authentication_limit,iam_totp_authentication_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", SYSTEM).id();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_security_audit", "iam_browser_session", "iam_resource_credential")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS resource_credential_http_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS resource_credential_http_fault()").update();
	}

	@Test
	void lifecycleDeliversSecretsOnceAndQueriesAndAuditsOnlyShowPublicFacts() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			assertThat(get(http, path(), session).statusCode()).isEqualTo(404);
			String code = freshCode(factor);
			var issued = postJson(http, path() + "/rotate", session, body(0, code));
			assertThat(issued.statusCode()).isEqualTo(200); assertSecurityHeaders(issued);
			assertThat(JsonPath.<Map<String, Object>>read(issued.body(), "$")).containsOnlyKeys("credential", "secret");
			String secret = JsonPath.read(issued.body(), "$.secret");
			assertThat(secret).matches("[A-Za-z0-9_-]{43}");
			assertThat(this.credentials.authenticate(this.resourceId.toString(), secret)).isPresent();
			String hash = this.jdbc.sql("SELECT secret_hash FROM iam_resource_credential").query(String.class).single();
			var detail = get(http, path(), session);
			assertThat(detail.statusCode()).isEqualTo(200); assertSecurityHeaders(detail);
			assertThat(JsonPath.<Map<String, Object>>read(detail.body(), "$")).containsOnlyKeys("resourceId", "status", "version", "createdAt", "rotatedAt", "updatedAt")
					.containsEntry("resourceId", this.resourceId.toString()).containsEntry("status", "ACTIVE").containsEntry("version", 1);
			var events = get(http, "/api/admin/audits?action=RESOURCE_CREDENTIAL_ISSUED", session);
			assertThat(events.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<String>read(events.body(), "$.items[0].targetType")).isEqualTo("RESOURCE");
			assertThat(JsonPath.<String>read(events.body(), "$.items[0].source")).isEqualTo("browser:admin-resource-credential-rotate");
			assertThat(detail.body() + events.body()).doesNotContain(secret, hash, code, PASSWORD, factor.secret());
			assertThat(postJson(http, path() + "/rotate", session, body(1, code)).statusCode()).isEqualTo(400);
			nextWindow(factor);
			var disabled = postJson(http, path() + "/disable", session, body(1, freshCode(factor)));
			assertThat(disabled.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<String>read(disabled.body(), "$.status")).isEqualTo("DISABLED");
			assertThat(disabled.body()).doesNotContain(secret, hash, "secret");
			assertThat(this.credentials.authenticate(this.resourceId.toString(), secret)).isEmpty();
			nextWindow(factor);
			var rotated = postJson(http, path() + "/rotate", session, body(2, freshCode(factor)));
			assertThat(rotated.statusCode()).isEqualTo(200);
			String replacement = JsonPath.read(rotated.body(), "$.secret");
			assertThat(replacement).isNotEqualTo(secret);
			assertThat(JsonPath.<String>read(rotated.body(), "$.credential.status")).isEqualTo("ACTIVE");
			assertThat(this.credentials.authenticate(this.resourceId.toString(), secret)).isEmpty();
			assertThat(this.credentials.authenticate(this.resourceId.toString(), replacement)).isPresent();
			assertThat(this.resources.findById(this.resourceId).orElseThrow().version()).isEqualTo(1);
		}
	}

	@Test
	void businessFailuresRollBackTotpAndRepeatedDisableConsumesCodeWithoutChangingCredentialVersion() throws Exception {
		var factor = administrator(); var issued = this.credentials.rotateSecret(this.resourceId, 0, SYSTEM);
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor); String code = freshCode(factor); long before = lastStep(factor);
			assertThat(postJson(http, path() + "/rotate", session, body(0, code)).statusCode()).isEqualTo(409);
			assertThat(postJson(http, path() + "/disable", session, body(2, code)).statusCode()).isEqualTo(409);
			assertThat(postJson(http, "/api/admin/resources/" + UUID.randomUUID() + "/validation-credential/rotate", session, body(0, code)).statusCode()).isEqualTo(404);
			this.resources.setEnabled(this.resourceId, 1, false, SYSTEM);
			assertThat(postJson(http, path() + "/rotate", session, body(1, code)).statusCode()).isEqualTo(409);
			assertThat(lastStep(factor)).isEqualTo(before);
			assertThat(postJson(http, path() + "/disable", session, body(1, code)).statusCode()).isEqualTo(200);
			nextWindow(factor); code = freshCode(factor);
			assertThat(postJson(http, path() + "/disable", session, body(2, code)).statusCode()).isEqualTo(200);
			assertThat(this.credentials.findByResourceId(this.resourceId).orElseThrow().version()).isEqualTo(2);
			assertThat(postJson(http, path() + "/disable", session, body(2, code)).statusCode()).isEqualTo(400);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='resource_credential_disabled'").query(Long.class).single()).isEqualTo(1);
			assertThat(this.credentials.authenticate(this.resourceId.toString(), issued.secret())).isEmpty();
		}
	}

	@Test
	void endpointsRequireCurrentAdministratorMfaAndSameSessionCsrfAndOnlyGetOrPost() throws Exception {
		var factor = administrator();
		UUID ordinary = this.users.create("bobby", "Bob", SYSTEM).id();
		this.setups.complete(ordinary, this.setups.issue(ordinary, SYSTEM).token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var http = client()) {
			assertThat(get(http, path(), null).statusCode()).isEqualTo(401);
			String ordinarySession = login(http, "bobby");
			assertThat(get(http, path(), ordinarySession).statusCode()).isEqualTo(403);
			assertThat(postJson(http, path() + "/rotate", ordinarySession, body(0, freshCode(factor))).statusCode()).isEqualTo(403);
			String passwordSession = login(http, "alice");
			assertThat(get(http, path(), passwordSession).statusCode()).isEqualTo(403);
			assertThat(postJson(http, path() + "/rotate", passwordSession, body(0, freshCode(factor))).statusCode()).isEqualTo(403);
			String session = elevate(http, passwordSession, factor);
			String foreignCsrf = csrf(get(http, "/api/csrf", ordinarySession));
			for (String operation : List.of("rotate", "disable")) {
				assertThat(post(http, path() + "/" + operation, session, json(body(0, freshCode(factor)), null)).statusCode()).isEqualTo(403);
				assertThat(post(http, path() + "/" + operation, session, json(body(0, freshCode(factor)), foreignCsrf)).statusCode()).isEqualTo(403);
				assertThat(post(http, path() + "/" + operation, session, "version=0&code=123456").statusCode()).isEqualTo(415);
			}
			for (String method : List.of("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path())).header("Cookie", session)
						.method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			}
			this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			assertThat(get(http, path(), session).statusCode()).isEqualTo(403);
			assertThat(postJson(http, path() + "/rotate", session, body(0, freshCode(factor))).statusCode()).isEqualTo(403);
			assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "{}", "null", "[]", "{\"version\":0}", "{\"version\":0,\"code\":123456}", "{\"version\":0,\"code\":null}", "{\"version\":0,\"code\":\"123456\",\"secret\":\"chosen\"}", "{\"version\":0,\"code\":\"123456\",\"version\":0}", "{\"version\":0,\"code\":\"123456\"} {}", "{\"version\":\"0\",\"code\":\"123456\"}", "{\"version\":-1,\"code\":\"123456\"}", "{\"version\":0.0,\"code\":\"123456\"}", "{\"version\":0e0,\"code\":\"123456\"}", "{\"version\":true,\"code\":\"123456\"}", "{\"version\":null,\"code\":\"123456\"}", "{\"version\":9223372036854775808,\"code\":\"123456\"}" })
	void malformedJsonNeverConsumesTotpOrCreatesCredential(String payload) throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor); long step = lastStep(factor);
			for (String operation : List.of("rotate", "disable")) {
				var result = postJson(http, path() + "/" + operation, session, payload);
				assertThat(result.statusCode()).isEqualTo(400); assertSecurityHeaders(result);
			}
			assertThat(lastStep(factor)).isEqualTo(step); assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty();
		}
	}

	@Test
	void boundedUtf8BodiesStrictIdsAndQueriesAreEnforcedBeforeSensitiveWork() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor); long step = lastStep(factor);
			String token = csrf(get(http, "/api/csrf", session)); String payload = body(0, freshCode(factor));
			for (String query : List.of("?x=1", "?version=0")) {
				assertThat(get(http, path() + query, session).statusCode()).isEqualTo(400);
				assertThat(post(http, path() + "/rotate" + query, session, json(payload, token)).statusCode()).isEqualTo(400);
			}
			for (String id : List.of("invalid", "1-1-1-1-1")) {
				assertThat(get(http, "/api/admin/resources/" + id + "/validation-credential", session).statusCode()).isEqualTo(400);
			}
			assertThat(post(http, path() + "/disable", session, json(payload, token)).statusCode()).isEqualTo(400);
			String oversized = payload + " ".repeat(8192);
			assertThat(post(http, path() + "/rotate", session, json(oversized, token)).statusCode()).isEqualTo(413);
			var chunked = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path() + "/rotate"))
					.header("Cookie", session).header("Content-Type", "application/json").header("X-CSRF-TOKEN", token)
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversized.getBytes(StandardCharsets.UTF_8)))).build();
			assertThat(http.send(chunked, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(413);
			var badEncoding = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path() + "/rotate"))
					.header("Cookie", session).header("Content-Type", "application/json; charset=UTF-16").header("X-CSRF-TOKEN", token)
					.POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_16)).build();
			assertThat(http.send(badEncoding, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			byte[] malformed = { (byte) 0xc3, (byte) 0x28 };
			var malformedRequest = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path() + "/rotate"))
					.header("Cookie", session).header("Content-Type", "application/json").header("X-CSRF-TOKEN", token).POST(HttpRequest.BodyPublishers.ofByteArray(malformed)).build();
			assertThat(http.send(malformedRequest, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			var unacceptable = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path() + "/rotate"))
					.header("Cookie", session).header("Content-Type", "application/json").header("X-CSRF-TOKEN", token).header("Accept", "text/html").POST(HttpRequest.BodyPublishers.ofString(payload)).build();
			assertThat(http.send(unacceptable, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			var getBody = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path())).header("Cookie", session)
					.method("GET", HttpRequest.BodyPublishers.ofString("body")).build();
			assertThat(http.send(getBody, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400);
			assertThat(lastStep(factor)).isEqualTo(step); assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "issue:audit-error", "issue:audit-suppressed", "issue:audit-deferred", "issue:session-error", "issue:session-suppressed", "issue:session-deferred", "rotate:audit-deferred", "rotate:session-deferred", "disable:audit-deferred", "disable:session-deferred" })
	void faultsRollBackTotpCredentialSessionAndAuditWithoutPublishingASecret(String scenario) throws Exception {
		var factor = administrator(); String operation = scenario.split(":")[0]; String fault = scenario.split(":")[1];
		if (!operation.equals("issue")) { this.credentials.rotateSecret(this.resourceId, 0, SYSTEM); }
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor); String token = csrf(get(http, "/api/csrf", session));
			long step = lastStep(factor); var before = snapshot();
			boolean audit = fault.startsWith("audit"); boolean deferred = fault.endsWith("deferred");
			String body = fault.endsWith("suppressed") ? "RETURN NULL;" : "RAISE EXCEPTION 'test resource credential persistence failure';";
			String condition = audit ? "NEW.action LIKE 'resource_credential_%'" : "true";
			this.jdbc.sql("CREATE FUNCTION resource_credential_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN " + body + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER " : "CREATE TRIGGER ") + "resource_credential_http_fault " + (deferred ? "AFTER " : "BEFORE ")
					+ (audit ? "INSERT ON iam_security_audit" : "UPDATE ON iam_browser_session") + (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION resource_credential_http_fault()").update();
			var result = post(http, path() + (operation.equals("disable") ? "/disable" : "/rotate"), session, json(body(operation.equals("issue") ? 0 : 1, freshCode(factor)), token));
			assertThat(result.statusCode()).isEqualTo(503); assertSecurityHeaders(result);
			assertThat(result.body()).doesNotContain("secret", "credential", "createdAt");
			assertThat(lastStep(factor)).isEqualTo(step); assertThat(snapshot()).isEqualTo(before);
		}
	}

	@Test
	void queuedMutationRechecksAdministratorMembershipBeforeCommitting() throws Exception {
		var factor = administrator();
		try (var http = client(); var executor = Executors.newSingleThreadExecutor();
				var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			String session = elevate(http, login(http, "alice"), factor); String token = csrf(get(http, "/api/csrf", session)); long step = lastStep(factor);
			connection.setAutoCommit(false);
			try (var statement = connection.prepareStatement("SELECT id FROM iam_resource WHERE id=? FOR UPDATE")) { statement.setObject(1, this.resourceId); statement.executeQuery().close(); }
			var write = executor.submit(() -> post(http, path() + "/rotate", session, json(body(0, freshCode(factor)), token)));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_resource WHERE id%FOR UPDATE%'").query(Long.class).single() > 0);
				this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			}
			finally { connection.commit(); }
			assertThat(write.get(10, TimeUnit.SECONDS).statusCode()).isEqualTo(503);
			assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty(); assertThat(lastStep(factor)).isEqualTo(step);
		}
	}

	@Test
	void failedTotpAttemptsUseTheSharedOperationThrottle() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			for (int i = 0; i < 5; i++) { assertThat(postJson(http, path() + "/rotate", session, body(0, "invalid")).statusCode()).isEqualTo(400); }
			assertThat(postJson(http, path() + "/rotate", session, body(0, freshCode(factor))).statusCode()).isEqualTo(429);
			assertThat(this.credentials.findByResourceId(this.resourceId)).isEmpty();
		}
	}

	@Test
	void swaggerDescribesTypedJsonCsrfVersionZeroAndOneTimeDelivery() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor); var response = get(http, "/v3/api-docs", session);
			assertThat(response.statusCode()).isEqualTo(200);
			String path = "/api/admin/resources/{resourceId}/validation-credential";
			assertThat(JsonPath.<Map<String, Object>>read(response.body(), "$.paths")).containsKeys(path, path + "/rotate", path + "/disable");
			for (String operation : List.of("rotate", "disable")) {
				var spec = JsonPath.<Map<String, Object>>read(response.body(), "$.paths['" + path + "/" + operation + "'].post");
				assertThat(JsonPath.<Map<String, Object>>read(spec, "$.requestBody.content")).containsOnlyKeys("application/json");
				assertThat(JsonPath.<List<Map<String, Object>>>read(spec, "$.parameters")).anySatisfy(parameter -> assertThat(parameter).containsEntry("name", "X-CSRF-TOKEN").containsEntry("required", true));
				assertThat(JsonPath.<String>read(spec, "$.responses['200'].content['application/json'].schema['$ref']"))
						.endsWith(operation.equals("rotate") ? "/IdentityResourceSecretResponse" : "/IdentityResourceCredentialResponse");
			}
			assertThat(JsonPath.<List<String>>read(response.body(), "$.components.schemas.IdentityResourceCredentialChangeRequest.required")).containsExactlyInAnyOrder("version", "code");
			assertThat(JsonPath.<Boolean>read(response.body(), "$.components.schemas.IdentityResourceCredentialChangeRequest.additionalProperties")).isFalse();
			assertThat(JsonPath.<Boolean>read(response.body(), "$.components.schemas.IdentityResourceCredentialChangeRequest.properties.code.writeOnly")).isTrue();
		}
	}

	private String path() { return "/api/admin/resources/" + this.resourceId + "/validation-credential"; }
	private static String body(long version, String code) { return JSON.writeValueAsString(Map.of("version", version, "code", code)); }
	private HttpResponse<String> postJson(HttpClient http, String path, String session, String payload) throws Exception { return post(http, path, session, json(payload, csrf(get(http, "/api/csrf", session)))); }
	private List<List<String>> snapshot() { return List.of("iam_resource_credential", "iam_resource", "iam_security_audit").stream().map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList(); }
	private long lastStep(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single(); }
	private void nextWindow(IdentityTotpEnrollment factor) {
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=:step WHERE user_id=:id").param("step", Math.floorDiv(Instant.now().getEpochSecond(), 30)).param("id", factor.userId()).update();
	}
	private IdentityTotpEnrollment administrator() {
		UUID id = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(id, PASSWORD, context()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(id, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=last_used_step-1").update();
		return factor;
	}
	private String login(HttpClient http, String username) throws Exception {
		var csrf = get(http, "/api/csrf", null);
		var response = post(http, "/login", cookie(csrf), credentials(username, PASSWORD, csrf(csrf)));
		assertThat(response.statusCode()).isEqualTo(204); return cookie(response);
	}
	private String elevate(HttpClient http, String session, IdentityTotpEnrollment factor) throws Exception {
		var response = post(http, "/admin/mfa", session, "code=" + otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)) + "&_csrf=" + encode(csrf(get(http, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(204); return cookie(response);
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-resource-credential-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
