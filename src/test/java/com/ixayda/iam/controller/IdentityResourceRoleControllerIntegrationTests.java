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
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentityResources;

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

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityResourceRoleControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String DETAIL = "/api/admin/resource-roles";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:role-http-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private JdbcClient jdbc;
	private UUID resourceId;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_resource, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", SYSTEM).id();
	}

	@AfterEach
	void removeFaults() {
		this.jdbc.sql("DROP TRIGGER IF EXISTS role_http_fault ON iam_security_audit").update();
		this.jdbc.sql("DROP TRIGGER IF EXISTS role_http_fault ON iam_browser_session").update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS role_http_fault()").update();
	}

	@Test
	void createsOnlyTheRequestedRoleAndDoesNotConfuseRoleCodeWithOperationTotp() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			var result = postForm(client, path(), session, "roleCode=reader&displayName=" + encode("Cafe\u0301 😀") + "&code=" + code);
			assertThat(result.statusCode()).isEqualTo(201);
			assertSecurityHeaders(result);
			Map<String, Object> body = JsonPath.read(result.body(), "$");
			assertThat(body).containsOnlyKeys("id", "resourceId", "code", "displayName", "status", "version", "createdAt", "updatedAt")
					.containsEntry("resourceId", this.resourceId.toString()).containsEntry("code", "reader").containsEntry("displayName", "Café 😀");
			UUID roleId = UUID.fromString((String) body.get("id"));
			assertThat(result.headers().firstValue("Location")).contains(DETAIL + "/" + roleId);
			assertThat(get(client, DETAIL + "/" + roleId, session).statusCode()).isEqualTo(200);
			var audit = this.jdbc.sql("SELECT actor,source,correlation_id,target_type,target_id,target_user_id FROM iam_security_audit WHERE action = 'resource_role_created'").query().singleRow();
			assertThat(audit).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-role-create")
					.containsEntry("target_type", "role").containsEntry("target_id", roleId).containsEntry("target_user_id", null);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='totp_authenticated' AND correlation_id=:id").param("id", audit.get("correlation_id")).query(Long.class).single()).isEqualTo(1);
			assertThat(result.body()).doesNotContain(code, factor.secret(), PASSWORD);
			assertThat(postForm(client, path(), session, "roleCode=writer&displayName=Writer&code=" + code).statusCode()).isEqualTo(400);
			assertThat(this.roles.findByCode(this.resourceId, "writer")).isEmpty();
		}
	}

	@Test
	void versionsAndParentStateAreEnforcedWithoutConsumingRejectedOperations() throws Exception {
		var factor = administrator();
		var role = this.roles.create(this.resourceId, "reader", "Reader", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			assertThat(postForm(client, DETAIL + "/" + role.id() + "/name", session, "version=2&displayName=Read&code=" + code).statusCode()).isEqualTo(409);
			assertThat(postForm(client, DETAIL + "/" + role.id() + "/name", session, "version=1&displayName=Read&code=" + code).statusCode()).isEqualTo(200);
			this.resources.setEnabled(this.resourceId, 1, false, SYSTEM);
			nextWindow(factor);
			code = freshCode(factor);
			long step = lastStep(factor);
			assertThat(postForm(client, path(), session, "roleCode=writer&displayName=Writer&code=" + code).statusCode()).isEqualTo(409);
			assertThat(postForm(client, DETAIL + "/" + role.id() + "/enable", session, "version=2&code=" + code).statusCode()).isEqualTo(409);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(postForm(client, DETAIL + "/" + role.id() + "/disable", session, "version=2&code=" + code).statusCode()).isEqualTo(200);
			this.resources.setEnabled(this.resourceId, 2, true, SYSTEM);
			nextWindow(factor);
			assertThat(postForm(client, DETAIL + "/" + role.id() + "/enable", session, "version=3&code=" + freshCode(factor)).statusCode()).isEqualTo(200);
			var changed = this.roles.findById(role.id()).orElseThrow();
			assertThat(changed.version()).isEqualTo(4);
			assertThat(changed.code()).isEqualTo(role.code());
			assertThat(changed.resourceId()).isEqualTo(this.resourceId);
		}
	}

	@Test
	void duplicateCodesAndMissingTargetsReturnConflictsOrNotFoundAfterVerification() throws Exception {
		var factor = administrator();
		this.roles.create(this.resourceId, "reader", "Reader", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String code = freshCode(factor);
			long step = lastStep(factor);
			assertThat(postForm(client, path(), session, "roleCode=reader&displayName=Other&code=" + code).statusCode()).isEqualTo(409);
			assertThat(postForm(client, DETAIL + "/" + UUID.randomUUID() + "/disable", session, "version=1&code=" + code).statusCode()).isEqualTo(404);
			assertThat(postForm(client, "/api/admin/resources/" + UUID.randomUUID() + "/roles", session, "roleCode=reader&displayName=Other&code=" + code).statusCode()).isEqualTo(404);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(postForm(client, path(), session, "roleCode=writer&displayName=Writer&code=" + code).statusCode()).isEqualTo(201);
		}
	}

	@Test
	void accessRequiresCurrentAdministratorMfaAndDoesNotAcceptOtherMethodsOrFields() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			assertThat(get(client, path(), null).statusCode()).isEqualTo(401);
			String password = login(client, "alice");
			assertThat(get(client, path(), password).statusCode()).isEqualTo(403);
			assertThat(postForm(client, path(), password, "roleCode=reader&displayName=Reader&code=" + freshCode(factor)).statusCode()).isEqualTo(403);
			String session = elevate(client, password, factor);
			assertThat(get(client, path(), session).statusCode()).isEqualTo(200);
			String body = "roleCode=reader&displayName=Reader&code=" + freshCode(factor);
			assertThat(post(client, path(), session, body).statusCode()).isEqualTo(403);
			for (String extra : List.of("&roleCode=writer", "&actor=other", "&resourceId=" + UUID.randomUUID(), "&version=1")) {
				assertThat(postForm(client, path(), session, body + extra).statusCode()).isEqualTo(400);
			}
			assertThat(postForm(client, path() + "?roleCode=writer", session, body).statusCode()).isEqualTo(400);
			assertThat(post(client, path(), session, credentials("ignored", "ignored", csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(415);
			for (String method : List.of("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")) {
				var response = client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path())).header("Cookie", session)
						.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
				assertThat(response.statusCode()).isEqualTo(403);
			}
			this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			assertThat(get(client, path(), session).statusCode()).isEqualTo(403);
			assertThat(this.roles.search(this.resourceId, null, 100, null).items()).isEmpty();
		}
	}

	@Test
	void paginationAndCursorsStayBoundToTheParentResourceAndStatus() throws Exception {
		var factor = administrator();
		for (int i = 0; i < 3; i++) { this.roles.create(this.resourceId, "reader_" + i, "Reader " + i, SYSTEM); }
		var other = this.resources.create("urn:example:billing", "Billing", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var first = get(client, path() + "?status=ACTIVE&pageSize=2", session);
			assertThat(first.statusCode()).isEqualTo(200);
			List<String> ids = JsonPath.read(first.body(), "$.items[*].id");
			assertThat(ids).hasSize(2);
			String cursor = JsonPath.read(first.body(), "$.nextCursor");
			var last = get(client, path() + "?status=ACTIVE&cursor=" + encode(cursor), session);
			assertThat(last.statusCode()).isEqualTo(200);
			List<String> remaining = JsonPath.read(last.body(), "$.items[*].id");
			assertThat(remaining).hasSize(1).doesNotContainAnyElementsOf(ids);
			assertThat((Object) JsonPath.read(last.body(), "$.nextCursor")).isNull();
			assertThat(get(client, "/api/admin/resources/" + other.id() + "/roles?status=ACTIVE&cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			assertThat(get(client, path() + "?status=DISABLED&cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			assertThat(get(client, "/api/admin/resources/" + UUID.randomUUID() + "/roles", session).statusCode()).isEqualTo(404);
			for (String query : List.of("status=active", "status=", "pageSize=0", "pageSize=101", "pageSize=1&pageSize=2", "cursor=!!!", "cursor=", "roleCode=reader", "actor=other")) {
				assertThat(get(client, path() + "?" + query, session).statusCode()).as(query).isEqualTo(400);
			}
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-error", "audit-suppressed", "audit-deferred", "session-error", "session-suppressed", "session-deferred" })
	void failedMandatoryWritesAndCommitCannotPublishOrPartlyApplyRoles(String fault) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			long step = lastStep(factor);
			var before = this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list();
			boolean audit = fault.startsWith("audit");
			String condition = audit ? "NEW.action = 'resource_role_created'" : "true";
			String body = fault.endsWith("suppressed") ? "RETURN NULL;" : "RAISE EXCEPTION 'test role storage failure';";
			this.jdbc.sql("CREATE FUNCTION role_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN " + body + " END IF; RETURN NEW; END $$").update();
			boolean deferred = fault.endsWith("deferred");
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " role_http_fault " + (deferred ? "AFTER" : "BEFORE")
					+ (audit ? " INSERT ON iam_security_audit" : " UPDATE ON iam_browser_session")
					+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION role_http_fault()").update();
			var response = post(client, path(), session, "roleCode=reader&displayName=Reader&code=" + freshCode(factor) + "&_csrf=" + encode(token));
			assertThat(response.statusCode()).isEqualTo(503);
			assertSecurityHeaders(response);
			assertThat(response.body()).doesNotContain("reader", "Reader", "createdAt");
			assertThat(this.roles.findByCode(this.resourceId, "reader")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list()).isEqualTo(before);
		}
	}

	@Test
	void swaggerDescribesRoleTargetsBodiesAndIndependentPublicRoleCodes() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var spec = get(client, "/v3/api-docs", session);
			assertThat(spec.statusCode()).isEqualTo(200);
			Map<String, Object> paths = JsonPath.read(spec.body(), "$.paths");
			assertThat(paths).containsKeys("/api/admin/resources/{resourceId}/roles", DETAIL + "/{roleId}", DETAIL + "/{roleId}/name", DETAIL + "/{roleId}/disable", DETAIL + "/{roleId}/enable");
			assertThat((Boolean) JsonPath.read(spec.body(), "$.components.schemas.IdentityResourceRoleCreateRequest.properties.code.writeOnly")).isTrue();
			List<String> required = JsonPath.read(spec.body(), "$.components.schemas.IdentityResourceRoleCreateRequest.required");
			assertThat(required).containsExactlyInAnyOrder("roleCode", "displayName", "code");
			assertThat(spec.body()).contains("createResourceRole", "searchResourceRoles", "getResourceRole", "updateResourceRoleName", "disableResourceRole", "enableResourceRole");
		}
	}

	private String path() { return "/api/admin/resources/" + this.resourceId + "/roles"; }

	private HttpResponse<String> postForm(HttpClient client, String path, String session, String body) throws Exception {
		return post(client, path, session, body + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
	}

	private long lastStep(IdentityTotpEnrollment factor) {
		return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single();
	}

	private void nextWindow(IdentityTotpEnrollment factor) {
		// Test fixture only: represent a later accepted TOTP window without waiting on wall-clock time.
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=:step WHERE user_id=:id")
				.param("step", Math.floorDiv(Instant.now().getEpochSecond(), 30)).param("id", factor.userId()).update();
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
			Path path = Files.createTempFile("iam-role-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
