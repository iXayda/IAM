package com.ixayda.iam.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.IdentityUserSetups;

import com.jayway.jsonpath.JsonPath;

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
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityResourceControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/admin/resources";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:resource-http-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityResources resources;
	@Autowired private JdbcClient jdbc;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_resource, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_security_audit", "iam_browser_session")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS resource_http_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS resource_http_fault()").update();
	}

	@Test
	void createsAnImmutableResourceAndReturnsOnlyItsPublicFieldsAndTrustedAudit() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			Object passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			Object management = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			String code = freshCode(factor);
			var created = postForm(client, PATH, session, "audience=urn:example:orders&displayName=" + encode("Cafe\u0301 😀") + "&code=" + code);
			assertThat(created.statusCode()).isEqualTo(201);
			assertSecurityHeaders(created);
			Map<String, Object> body = JsonPath.read(created.body(), "$");
			assertThat(body).containsOnlyKeys("id", "audience", "displayName", "status", "version", "createdAt", "updatedAt")
					.containsEntry("audience", "urn:example:orders").containsEntry("displayName", "Café 😀").containsEntry("status", "ACTIVE");
			UUID id = UUID.fromString((String) body.get("id"));
			assertThat(created.headers().firstValue("Location")).contains(PATH + "/" + id);
			assertThat(get(client, PATH + "/" + id, session).statusCode()).isEqualTo(200);
			var event = this.jdbc.sql("SELECT actor, source, correlation_id, target_user_id, target_type, target_id FROM iam_security_audit WHERE action = 'resource_created'").query().singleRow();
			assertThat(event).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-resource-create")
					.containsEntry("target_user_id", null).containsEntry("target_type", "resource").containsEntry("target_id", id);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'totp_authenticated' AND correlation_id = :id")
					.param("id", event.get("correlation_id")).query(Long.class).single()).isEqualTo(1);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(management);
			assertThat(created.body()).doesNotContain(code, factor.secret(), PASSWORD, "clientSecret", "credentialVersion");
			var replay = postForm(client, PATH, session, "audience=urn:example:other&displayName=Other&code=" + code);
			assertThat(replay.statusCode()).isEqualTo(400);
			assertThat(this.resources.findByAudience("urn:example:other")).isEmpty();
		}
	}

	@Test
	void changesNamesAndStateWithVersionChecksAndNeverRevivesOrReplacesIdentity() throws Exception {
		var factor = administrator();
		var resource = this.resources.create("urn:example:orders", "Orders", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			var conflict = postForm(client, PATH + "/" + resource.id() + "/name", session, "version=2&displayName=Changed&code=" + code);
			assertThat(conflict.statusCode()).isEqualTo(409);
			assertThat(lastStep(factor)).isLessThan(Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1);
			var renamed = postForm(client, PATH + "/" + resource.id() + "/name", session, "version=1&displayName=Changed&code=" + code);
			assertThat(renamed.statusCode()).isEqualTo(200);
			assertThat((Number) JsonPath.read(renamed.body(), "$.version")).isEqualTo(2);
			// Reset only the test fixture's replay marker to represent the next TOTP window.
			nextWindow(factor);
			var unchanged = postForm(client, PATH + "/" + resource.id() + "/name", session, "version=2&displayName=Changed&code=" + freshCode(factor));
			assertThat(unchanged.statusCode()).isEqualTo(200);
			assertThat((Number) JsonPath.read(unchanged.body(), "$.version")).isEqualTo(2);
			nextWindow(factor);
			var disabled = postForm(client, PATH + "/" + resource.id() + "/disable", session, "version=2&code=" + freshCode(factor));
			assertThat(disabled.statusCode()).isEqualTo(200);
			assertThat((String) JsonPath.read(disabled.body(), "$.status")).isEqualTo("DISABLED");
			nextWindow(factor);
			var enabled = postForm(client, PATH + "/" + resource.id() + "/enable", session, "version=3&code=" + freshCode(factor));
			assertThat(enabled.statusCode()).isEqualTo(200);
			var finalResource = this.resources.findById(resource.id()).orElseThrow();
			assertThat(finalResource.id()).isEqualTo(resource.id());
			assertThat(finalResource.audience()).isEqualTo(resource.audience());
			assertThat(finalResource.version()).isEqualTo(4);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'resource_updated'").query(Long.class).single()).isEqualTo(1);
		}
	}

	@Test
	void duplicateAudienceAndUnknownTargetsDoNotConsumeOrPartlyApplyAnOperation() throws Exception {
		var factor = administrator();
		var resource = this.resources.create("urn:example:orders", "Original", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			long step = lastStep(factor);
			String code = freshCode(factor);
			assertThat(postForm(client, PATH, session, "audience=urn:example:orders&displayName=Replacement&code=" + code).statusCode()).isEqualTo(409);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.resources.findById(resource.id())).contains(resource);
			assertThat(postForm(client, PATH + "/" + UUID.randomUUID() + "/disable", session, "version=1&code=" + code).statusCode()).isEqualTo(404);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(postForm(client, PATH, session, "audience=urn:example:new&displayName=New&code=" + code).statusCode()).isEqualTo(201);
		}
	}

	@Test
	void readAndWriteRequireCurrentAdministratorMfaAndStateIsRecheckedOnEveryRequest() throws Exception {
		var factor = administrator();
		var regular = this.users.create("bobby", "Bob", SYSTEM);
		var proof = this.setups.issue(regular.id(), SYSTEM);
		this.setups.complete(regular.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var client = client()) {
			assertThat(get(client, PATH, null).statusCode()).isEqualTo(401);
			String ordinary = login(client, "bobby");
			assertThat(get(client, PATH, ordinary).statusCode()).isEqualTo(403);
			assertThat(postForm(client, PATH, ordinary, "audience=urn:orders&displayName=Orders&code=123456").statusCode()).isEqualTo(403);
			String passwordOnly = login(client, "alice");
			assertThat(get(client, PATH, passwordOnly).statusCode()).isEqualTo(403);
			String session = elevate(client, passwordOnly, factor);
			assertThat(get(client, PATH, session).statusCode()).isEqualTo(200);
			this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id = :id").param("id", factor.userId()).update();
			assertThat(get(client, PATH, session).statusCode()).isEqualTo(403);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_resource").query(Long.class).single()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "status=active", "status=", "pageSize=0", "pageSize=101", "pageSize=", "pageSize=1&pageSize=2", "pageSize=%202", "cursor=", "cursor=!!!", "audience=urn:orders", "actor=admin" })
	void rejectsUnspecifiedRepeatedAndInvalidQueries(String query) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = get(client, PATH + "?" + query, session);
			assertThat(response.statusCode()).isEqualTo(400);
			assertSecurityHeaders(response);
		}
	}

	@Test
	void pagesThroughResourcesAndBindsCursorsToTheStatusFilter() throws Exception {
		var factor = administrator();
		for (int i = 1; i <= 4; i++) { this.resources.create("urn:fixture:" + i, "Fixture " + i, SYSTEM); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var first = get(client, PATH + "?status=ACTIVE&pageSize=2", session);
			assertThat(first.statusCode()).isEqualTo(200);
			List<String> firstIds = JsonPath.read(first.body(), "$.items[*].id");
			assertThat(firstIds).hasSize(2);
			String cursor = JsonPath.read(first.body(), "$.nextCursor");
			var last = get(client, PATH + "?status=ACTIVE&pageSize=2&cursor=" + encode(cursor), session);
			List<String> lastIds = JsonPath.read(last.body(), "$.items[*].id");
			assertThat(lastIds).hasSize(2).doesNotContainAnyElementsOf(firstIds);
			assertThat((Object) JsonPath.read(last.body(), "$.nextCursor")).isNull();
			assertThat(get(client, PATH + "?cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			assertThat(get(client, PATH + "?status=DISABLED&cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-error", "audit-suppressed", "audit-deferred", "session-error", "session-suppressed", "session-deferred" })
	void mandatoryStorageAndLateCommitFailuresNeverPublishOrLeavePartialChanges(String fault) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			long step = lastStep(factor);
			var before = this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list();
			boolean audit = fault.startsWith("audit");
			String condition = audit ? "NEW.action = 'resource_created'" : "true";
			String body = fault.endsWith("suppressed") ? "RETURN NULL;" : "RAISE EXCEPTION 'test resource storage failure';";
			this.jdbc.sql("CREATE FUNCTION resource_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN " + body + " END IF; RETURN NEW; END $$").update();
			boolean deferred = fault.endsWith("deferred");
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " resource_http_fault " + (deferred ? "AFTER" : "BEFORE")
					+ (audit ? " INSERT ON iam_security_audit" : " UPDATE ON iam_browser_session")
					+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION resource_http_fault()").update();
			var response = post(client, PATH, session, "audience=urn:example:failure&displayName=Failure&code=" + freshCode(factor) + "&_csrf=" + encode(token));
			assertThat(response.statusCode()).isEqualTo(503);
			assertThat(response.body()).doesNotContain("urn:example:failure", "Failure", "createdAt");
			assertSecurityHeaders(response);
			assertThat(this.resources.findByAudience("urn:example:failure")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list()).isEqualTo(before);
		}
	}

	@Test
	void requestBoundaryRejectsCsrfSmugglingUnexpectedFieldsAndOtherMethods() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String body = "audience=urn:orders&displayName=Orders&code=" + freshCode(factor);
			assertThat(post(client, PATH, session, body).statusCode()).isEqualTo(403);
			for (String extra : List.of("&actor=user:other", "&audience=urn:other", "&version=1")) {
				assertThat(postForm(client, PATH, session, body + extra).statusCode()).isEqualTo(400);
			}
			assertThat(postForm(client, PATH + "?displayName=Other", session, body).statusCode()).isEqualTo(400);
			var json = post(client, PATH, session, credentials("ignored", "ignored", csrf(get(client, "/api/csrf", session))));
			assertThat(json.statusCode()).isEqualTo(415);
			var spoof = client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
					.header("Cookie", session).header("status", "DISABLED").GET().build(), HttpResponse.BodyHandlers.ofString());
			assertThat(spoof.statusCode()).isEqualTo(200);
			for (String method : List.of("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")) {
				var response = client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH))
						.header("Cookie", session).method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
				assertThat(response.statusCode()).isEqualTo(403);
			}
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_resource").query(Long.class).single()).isZero();
		}
	}

	@Test
	void swaggerDescribesAllResourceOperationsAndSecretWriteOnlyFields() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var document = get(client, "/v3/api-docs", session);
			assertThat(document.statusCode()).isEqualTo(200);
			Map<String, Object> paths = JsonPath.read(document.body(), "$.paths");
			assertThat(paths).containsKeys(PATH, PATH + "/{resourceId}", PATH + "/{resourceId}/name", PATH + "/{resourceId}/disable", PATH + "/{resourceId}/enable");
			assertThat((Boolean) JsonPath.read(document.body(), "$.components.schemas.IdentityResourceCreateRequest.properties.code.writeOnly")).isTrue();
			assertThat((Number) JsonPath.read(document.body(), "$.components.schemas.IdentityResourceStateRequest.properties.version.minimum")).isEqualTo(1);
			assertThat(document.body()).contains("createResource", "getResource", "searchResources", "updateResourceName", "disableResource", "enableResource");
		}
	}

	@Test
	void sharesFailedTotpBudgetsWithExistingAdministratorOperations() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			for (int i = 0; i < 5; i++) {
				assertThat(postForm(client, PATH, session, "audience=urn:orders&displayName=Orders&code=invalid").statusCode()).isEqualTo(400);
			}
			assertThat(postForm(client, PATH, session, "audience=urn:orders&displayName=Orders&code=" + freshCode(factor)).statusCode()).isEqualTo(429);
			assertThat(postForm(client, "/api/admin/users", session, "username=bobby&displayName=Bob&code=" + freshCode(factor)).statusCode()).isEqualTo(429);
			assertThat(this.resources.findByAudience("urn:orders")).isEmpty();
			assertThat(this.users.findByUsername("bobby")).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "management" })
	void expiryDuringTheChangeRollsBackItsResourceAuditAndTotp(String deadline) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			var evidence = (IdentityAdministratorAuthentication) attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			long expires = System.currentTimeMillis() + 1_000;
			long passwordTime = deadline.equals("password") ? expires - 28_800_000 : System.currentTimeMillis() - 1_200_000;
			Instant verifiedAt = deadline.equals("management") ? Instant.ofEpochMilli(expires - 900_000) : evidence.verifiedAt();
			replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
			replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION, new IdentityAdministratorAuthentication(
					evidence.userId(), evidence.factorId(), evidence.credentialVersion(), passwordTime, verifiedAt));
			long step = lastStep(factor);
			long auditCount = this.jdbc.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single();
			this.jdbc.sql("CREATE FUNCTION resource_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'resource_created' THEN PERFORM pg_sleep(1.2); END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER resource_http_fault BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION resource_http_fault()").update();
			var result = post(client, PATH, session, "audience=urn:expired&displayName=Expired&code=" + freshCode(factor) + "&_csrf=" + encode(token));
			assertThat(result.statusCode()).isEqualTo(503);
			assertThat(this.resources.findByAudience("urn:expired")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit").query(Long.class).single()).isEqualTo(auditCount);
		}
	}

	private void replaceAttribute(String cookie, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update();
	}

	private HttpResponse<String> postForm(HttpClient client, String path, String session, String body) throws Exception {
		return post(client, path, session, body + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
	}

	private void nextWindow(IdentityTotpEnrollment factor) {
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step = :step WHERE user_id = :id")
				.param("step", Math.floorDiv(Instant.now().getEpochSecond(), 30)).param("id", factor.userId()).update();
	}
	private long lastStep(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id = :id").param("id", factor.userId()).query(Long.class).single(); }
	private Object attribute(String cookie, String name) {
		byte[] value = this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id = a.session_primary_id WHERE s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).single();
		return SerializationUtils.deserialize(value);
	}
	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step = last_used_step - 1").update();
		return factor;
	}
	private String login(HttpClient client, String username) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(username, PASSWORD, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private String elevate(HttpClient client, String session, IdentityTotpEnrollment factor) throws Exception {
		var response = post(client, "/admin/mfa", session, "code=" + otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-resource-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
