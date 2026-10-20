package com.ixayda.iam.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityUserRoles;
import com.ixayda.iam.service.IdentityUserStates;
import com.ixayda.iam.service.IdentityUsers;

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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserRoleControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:binding-http-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUserRoles bindings;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user,iam_resource,iam_browser_session,iam_security_audit,iam_password_authentication_limit,iam_totp_authentication_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.userId = this.users.create("bobby", "Bob", SYSTEM).id();
		this.resourceId = this.resources.create("urn:example:orders", "Orders", SYSTEM).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", SYSTEM).id();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_security_audit", "iam_browser_session")) { this.jdbc.sql("DROP TRIGGER IF EXISTS binding_http_fault ON " + table).update(); }
		this.jdbc.sql("DROP FUNCTION IF EXISTS binding_http_fault()").update();
	}

	@Test
	void grantAndRevokePublishOnlyTheTargetBindingAndAtomicUserAndRoleAudit() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			String code = freshCode(factor);
			var result = postForm(client, changePath("grant"), session, "version=0&code=" + code);
			assertThat(result.statusCode()).isEqualTo(200);
			assertSecurityHeaders(result);
			Map<String, Object> body = JsonPath.read(result.body(), "$");
			assertThat(body).containsOnlyKeys("userId", "resourceId", "roleId", "changed", "version")
					.containsEntry("userId", this.userId.toString()).containsEntry("resourceId", this.resourceId.toString())
					.containsEntry("roleId", this.roleId.toString()).containsEntry("changed", true).containsEntry("version", 1);
			var page = get(client, searchPath(), session);
			assertThat((Number) JsonPath.read(page.body(), "$.version")).isEqualTo(1);
			List<Map<String, Object>> items = JsonPath.read(page.body(), "$.items");
			assertThat(items).singleElement().satisfies(item -> assertThat(item).containsOnlyKeys("userId", "resourceId", "roleId", "createdAt"));
			var audit = this.jdbc.sql("SELECT actor,source,correlation_id,target_user_id,target_type,target_id FROM iam_security_audit WHERE action='user_role_granted'").query().singleRow();
			assertThat(audit).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-user-role-grant")
					.containsEntry("target_user_id", this.userId).containsEntry("target_type", "role").containsEntry("target_id", this.roleId);
			var events = get(client, "/api/admin/audits?action=USER_ROLE_GRANTED&targetUserId=" + this.userId, session);
			assertThat(events.statusCode()).isEqualTo(200);
			assertThat((String) JsonPath.read(events.body(), "$.items[0].targetType")).isEqualTo("ROLE");
			assertThat((String) JsonPath.read(events.body(), "$.items[0].targetId")).isEqualTo(this.roleId.toString());
			assertThat(postForm(client, changePath("revoke"), session, "version=1&code=" + code).statusCode()).isEqualTo(400);
			nextWindow(factor);
			assertThat(postForm(client, changePath("revoke"), session, "version=1&code=" + freshCode(factor)).statusCode()).isEqualTo(200);
			var empty = get(client, searchPath(), session);
			assertThat((List<?>) JsonPath.read(empty.body(), "$.items")).isEmpty();
			assertThat((Number) JsonPath.read(empty.body(), "$.version")).isEqualTo(2);
			assertThat(result.body() + page.body() + events.body()).doesNotContain(PASSWORD, factor.secret(), code);
		}
	}

	@Test
	void businessConflictsRollBackTotpButAnAuthorizedNoOpConsumesIt() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			String code = freshCode(factor);
			long before = lastStep(factor);
			assertThat(postForm(client, changePath("grant"), session, "version=1&code=" + code).statusCode()).isEqualTo(409);
			assertThat(postForm(client, "/api/admin/users/" + UUID.randomUUID() + "/roles/" + this.roleId + "/grant", session, "version=0&code=" + code).statusCode()).isEqualTo(404);
			assertThat(postForm(client, "/api/admin/users/" + this.userId + "/roles/" + UUID.randomUUID() + "/grant", session, "version=0&code=" + code).statusCode()).isEqualTo(404);
			assertThat(lastStep(factor)).isEqualTo(before);
			var noOp = postForm(client, changePath("revoke"), session, "version=0&code=" + code);
			assertThat(noOp.statusCode()).isEqualTo(200);
			assertThat((Boolean) JsonPath.read(noOp.body(), "$.changed")).isFalse();
			assertThat(lastStep(factor)).isGreaterThan(before);
			assertThat(postForm(client, changePath("grant"), session, "version=0&code=" + code).statusCode()).isEqualTo(400);
			assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).version()).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action IN ('user_role_granted','user_role_revoked')").query(Long.class).single()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "user", "resource", "role" })
	void inactiveSubjectsStillAllowInspectionAndRevocation(String subject) throws Exception {
		var factor = administrator();
		this.bindings.change(this.userId, this.roleId, 0, true, SYSTEM);
		switch (subject) {
			case "user" -> this.states.disable(this.userId, SYSTEM);
			case "resource" -> this.resources.setEnabled(this.resourceId, 1, false, SYSTEM);
			default -> this.roles.setEnabled(this.roleId, 1, false, SYSTEM);
		}
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			assertThat(get(client, searchPath(), session).statusCode()).isEqualTo(200);
			String code = freshCode(factor);
			assertThat(postForm(client, changePath("grant"), session, "version=1&code=" + code).statusCode()).isEqualTo(409);
			assertThat(postForm(client, changePath("revoke"), session, "version=1&code=" + code).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void requestsRequireCurrentAdministratorMfaCsrfAndExactMethodAndFields() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			assertThat(get(client, searchPath(), null).statusCode()).isEqualTo(401);
			String password = login(client);
			assertThat(get(client, searchPath(), password).statusCode()).isEqualTo(403);
			String session = elevate(client, password, factor);
			String body = "version=0&code=" + freshCode(factor);
			assertThat(post(client, changePath("grant"), session, body).statusCode()).isEqualTo(403);
			for (String extra : List.of("&version=1", "&actor=other", "&roleId=" + UUID.randomUUID(), "&resourceId=" + UUID.randomUUID())) {
				assertThat(postForm(client, changePath("grant"), session, body + extra).statusCode()).isEqualTo(400);
			}
			for (String version : List.of("", "-1", "01", "+0", "9223372036854775808")) {
				assertThat(postForm(client, changePath("grant"), session, "version=" + encode(version) + "&code=" + freshCode(factor)).statusCode()).isEqualTo(400);
			}
			assertThat(postForm(client, changePath("grant"), session, "code=" + freshCode(factor)).statusCode()).isEqualTo(400);
			assertThat(postForm(client, changePath("grant") + "?version=0", session, body).statusCode()).isEqualTo(400);
			assertThat(post(client, changePath("grant"), session, credentials("ignored", "ignored", csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(415);
			for (String method : List.of("PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")) {
				var response = client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + searchPath())).header("Cookie", session)
						.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
				assertThat(response.statusCode()).isEqualTo(403);
			}
			this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			assertThat(get(client, searchPath(), session).statusCode()).isEqualTo(403);
			assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).version()).isZero();
		}
	}

	@Test
	void paginationRejectsDifferentUsersResourcesAndChangedAssignmentRevisions() throws Exception {
		var factor = administrator();
		for (int i = 0; i < 3; i++) { this.bindings.change(this.userId, this.roles.create(this.resourceId, "role_" + i, "Role", SYSTEM).id(), i, true, SYSTEM); }
		var other = this.resources.create("urn:other", "Other", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			var first = get(client, searchPath() + "?pageSize=2", session);
			assertThat(first.statusCode()).isEqualTo(200);
			List<String> initial = JsonPath.read(first.body(), "$.items[*].roleId");
			assertThat(initial).hasSize(2);
			String cursor = JsonPath.read(first.body(), "$.nextCursor");
			var last = get(client, searchPath() + "?cursor=" + encode(cursor), session);
			assertThat(last.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<List<String>>read(last.body(), "$.items[*].roleId")).hasSize(1).doesNotContainAnyElementsOf(initial);
			assertThat(get(client, "/api/admin/users/" + factor.userId() + "/resources/" + this.resourceId + "/roles?cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			assertThat(get(client, "/api/admin/users/" + this.userId + "/resources/" + other.id() + "/roles?cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			for (String query : List.of("pageSize=", "pageSize=0", "pageSize=101", "pageSize=1&pageSize=2", "cursor=", "cursor=!!!", "status=ACTIVE", "actor=other")) {
				assertThat(get(client, searchPath() + "?" + query, session).statusCode()).as(query).isEqualTo(400);
			}
			this.bindings.change(this.userId, this.roleId, 3, true, SYSTEM);
			assertThat(get(client, searchPath() + "?cursor=" + encode(cursor), session).statusCode()).isEqualTo(409);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-error", "audit-suppressed", "audit-deferred", "session-error", "session-suppressed", "session-deferred" })
	void failedMandatoryWritesCannotPublishBindingOrConsumeTotp(String fault) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			String token = csrf(get(client, "/api/csrf", session));
			long step = lastStep(factor);
			var before = this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list();
			boolean audit = fault.startsWith("audit");
			String condition = audit ? "NEW.action='user_role_granted'" : "true";
			String body = fault.endsWith("suppressed") ? "RETURN NULL;" : "RAISE EXCEPTION 'test binding persistence failure';";
			this.jdbc.sql("CREATE FUNCTION binding_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN " + body + " END IF; RETURN NEW; END $$").update();
			boolean deferred = fault.endsWith("deferred");
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " binding_http_fault " + (deferred ? "AFTER" : "BEFORE")
					+ (audit ? " INSERT ON iam_security_audit" : " UPDATE ON iam_browser_session")
					+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION binding_http_fault()").update();
			var result = post(client, changePath("grant"), session, "version=0&code=" + freshCode(factor) + "&_csrf=" + encode(token));
			assertThat(result.statusCode()).isEqualTo(503);
			assertSecurityHeaders(result);
			assertThat(result.body()).doesNotContain("roleId", "resourceId", "changed");
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).version()).isZero();
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list()).isEqualTo(before);
		}
	}

	@Test
	void aTargetBeforeTheActorIsLockedFirstWithoutHoldingTheActorWhileWaiting() throws Exception {
		var factor = administrator();
		UUID target = new UUID(Long.MIN_VALUE, Long.MIN_VALUE);
		this.jdbc.sql("INSERT INTO iam_user(id,username,display_name,status) VALUES (:id,'charlie','Charlie','pending')").param("id", target).update();
		assertThat(target.compareTo(factor.userId())).isNegative();
		try (var client = client(); var executor = Executors.newSingleThreadExecutor();
				var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			String session = elevate(client, login(client), factor);
			String token = csrf(get(client, "/api/csrf", session));
			connection.setAutoCommit(false);
			try (var statement = connection.prepareStatement("SELECT id FROM iam_user WHERE id=? FOR UPDATE")) { statement.setObject(1, target); statement.executeQuery().close(); }
			var operation = executor.submit(() -> post(client, "/api/admin/users/" + target + "/roles/" + this.roleId + "/grant", session,
					"version=0&code=" + freshCode(factor) + "&_csrf=" + encode(token)));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR UPDATE%'").query(Long.class).single() > 0);
				new TransactionTemplate(this.transactions).executeWithoutResult(tx -> this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE NOWAIT").param("id", factor.userId()).query(UUID.class).single());
			}
			finally { connection.commit(); }
			assertThat(operation.get(10, TimeUnit.SECONDS).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void swaggerDescribesAllBindingOperationsVersionsAndWriteOnlyVerification() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			var spec = get(client, "/v3/api-docs", session);
			assertThat(spec.statusCode()).isEqualTo(200);
			Map<String, Object> paths = JsonPath.read(spec.body(), "$.paths");
			assertThat(paths).containsKeys("/api/admin/users/{userId}/resources/{resourceId}/roles", "/api/admin/users/{userId}/roles/{roleId}/grant", "/api/admin/users/{userId}/roles/{roleId}/revoke");
			assertThat((Boolean) JsonPath.read(spec.body(), "$.components.schemas.IdentityUserRoleChangeRequest.properties.code.writeOnly")).isTrue();
			List<String> required = JsonPath.read(spec.body(), "$.components.schemas.IdentityUserRoleChangeRequest.required");
			assertThat(required).containsExactlyInAnyOrder("version", "code");
			assertThat(spec.body()).contains("searchUserRoles", "grantUserRole", "revokeUserRole", "IdentityUserRolePageResponse");
			for (String action : List.of("grant", "revoke")) {
				Map<String, Object> operation = JsonPath.read(spec.body(), "$.paths['/api/admin/users/{userId}/roles/{roleId}/" + action + "'].post");
				assertThat(JsonPath.<String>read(operation, "$.responses['200'].content['application/json'].schema['$ref']")).endsWith("/IdentityUserRoleChangeResponse");
				List<Map<String, Object>> parameters = JsonPath.read(operation, "$.parameters");
				assertThat(parameters).anySatisfy(parameter -> assertThat(parameter).containsEntry("name", "X-CSRF-TOKEN").containsEntry("in", "header"));
			}
		}
	}

	@Test
	void selfAssignmentsUseTheSameUserLockAndDoNotChangeAdministratorMembership() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client), factor);
			var result = postForm(client, "/api/admin/users/" + factor.userId() + "/roles/" + this.roleId + "/grant", session,
					"version=0&code=" + freshCode(factor));
			assertThat(result.statusCode()).isEqualTo(200);
			assertThat(this.bindings.search(factor.userId(), this.resourceId, 20, null).items()).hasSize(1);
			assertThat(this.jdbc.sql("SELECT user_id FROM iam_administrator").query(UUID.class).list()).containsExactly(factor.userId());
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	private String searchPath() { return "/api/admin/users/" + this.userId + "/resources/" + this.resourceId + "/roles"; }
	private String changePath(String action) { return "/api/admin/users/" + this.userId + "/roles/" + this.roleId + "/" + action; }
	private HttpResponse<String> postForm(HttpClient client, String path, String session, String body) throws Exception {
		return post(client, path, session, body + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
	}
	private long lastStep(IdentityTotpEnrollment factor) {
		return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single();
	}
	private void nextWindow(IdentityTotpEnrollment factor) {
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=:step WHERE user_id=:id").param("step", Math.floorDiv(Instant.now().getEpochSecond(), 30)).param("id", factor.userId()).update();
	}
	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=last_used_step-1").update();
		return factor;
	}
	private String login(HttpClient client) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page)));
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
			Path path = Files.createTempFile("iam-binding-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
