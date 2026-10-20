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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityResourceRoles;
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
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
@Import(PostgreSqlTestConfiguration.class)
class IdentityClientControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/admin/clients";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:client-http-test", "internal:test", UUID.randomUUID());
	private static final JsonMapper JSON = new JsonMapper();
	private static final Path KEY_FILE = keyFile();
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private JdbcClient jdbc;
	@Autowired private PostgreSQLContainer postgres;
	private UUID resourceId;
	private UUID roleId;

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
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", SYSTEM).id();
	}

	@AfterEach
	void removeFaults() {
		for (String table : List.of("iam_security_audit", "iam_browser_session", "iam_client", "oauth2_registered_client")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS client_http_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS client_http_fault()").update();
	}

	@Test
	void creationDeliversTheSecretOnceAndPublicQueriesAndAuditCannotRetrieveIt() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String code = freshCode(factor);
			var created = postJson(http, PATH, session, createBody(code));
			assertThat(created.statusCode()).isEqualTo(201);
			assertSecurityHeaders(created);
			Map<String, Object> delivered = JsonPath.read(created.body(), "$");
			assertThat(delivered).containsOnlyKeys("client", "secret");
			String id = JsonPath.read(created.body(), "$.client.id");
			String secret = JsonPath.read(created.body(), "$.secret");
			assertThat(secret).matches("[A-Za-z0-9_-]{43}");
			assertThat(created.headers().firstValue("Location")).contains(PATH + "/" + id);
			Map<String, Object> client = JsonPath.read(created.body(), "$.client");
			assertThat(client).containsOnlyKeys("id", "configuration", "status", "version", "createdAt", "updatedAt", "secretRotatedAt")
					.containsEntry("status", "ACTIVE").containsEntry("version", 1);
			assertThat(JsonPath.<Map<String, Object>>read(client, "$.configuration")).containsEntry("displayName", "Orders app").containsEntry("resourceId", this.resourceId.toString());
			String hash = this.jdbc.sql("SELECT client_secret FROM oauth2_registered_client WHERE id=:id").param("id", id).query(String.class).single();
			assertThat(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(secret, hash)).isTrue();
			var detail = get(http, PATH + "/" + id, session);
			assertThat(detail.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<Map<String, Object>>read(detail.body(), "$")).isEqualTo(client);
			var page = get(http, PATH, session);
			assertThat(page.statusCode()).isEqualTo(200);
			List<Map<String, Object>> items = JsonPath.read(page.body(), "$.items");
			assertThat(items).singleElement().satisfies(item -> assertThat(item).containsOnlyKeys("id", "displayName", "resourceId", "status", "version", "createdAt", "updatedAt", "secretRotatedAt"));
			var audit = this.jdbc.sql("SELECT actor,source,target_user_id,target_type,target_id FROM iam_security_audit WHERE action='client_created'").query().singleRow();
			assertThat(audit).containsEntry("actor", "user:" + factor.userId()).containsEntry("source", "browser:admin-client-create")
					.containsEntry("target_user_id", null).containsEntry("target_type", "client").containsEntry("target_id", UUID.fromString(id));
			var events = get(http, "/api/admin/audits?action=CLIENT_CREATED", session);
			assertThat(events.statusCode()).isEqualTo(200);
			assertThat((String) JsonPath.read(events.body(), "$.items[0].targetType")).isEqualTo("CLIENT");
			assertThat(detail.body() + page.body() + events.body()).doesNotContain(secret, hash, "clientSecret", "clientSettings", "tokenSettings", PASSWORD, factor.secret(), code);
			assertThat(postJson(http, PATH, session, createBody(code)).statusCode()).isEqualTo(400);
			assertThat(this.clients.search(null, 100, null).items()).hasSize(1);
		}
	}

	@Test
	void configurationStateAndSecretRotationUseVersionsAndNeverReenableADisabledClient() throws Exception {
		var factor = administrator();
		var existing = this.clients.create(nativeConfiguration(), SYSTEM);
		String path = PATH + "/" + existing.client().id();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String code = freshCode(factor);
			String changed = JSON.writeValueAsString(Map.of("version", 1, "configuration", configuration("Orders renamed"), "code", code));
			assertThat(postJson(http, path + "/configuration", session, changed).statusCode()).isEqualTo(200);
			assertThat(this.clients.findById(existing.client().id()).orElseThrow().version()).isEqualTo(2);
			nextWindow(factor);
			var disabled = postJson(http, path + "/disable", session, changeBody(2, freshCode(factor)));
			assertThat(disabled.statusCode()).isEqualTo(200);
			assertThat((String) JsonPath.read(disabled.body(), "$.status")).isEqualTo("DISABLED");
			nextWindow(factor);
			var rotated = postJson(http, path + "/secret/rotate", session, changeBody(3, freshCode(factor)));
			assertThat(rotated.statusCode()).isEqualTo(200);
			String secret = JsonPath.read(rotated.body(), "$.secret");
			assertThat(secret).isNotEqualTo(existing.secret());
			assertThat((String) JsonPath.read(rotated.body(), "$.client.id")).isEqualTo(existing.client().id().toString());
			assertThat((String) JsonPath.read(rotated.body(), "$.client.status")).isEqualTo("DISABLED");
			String hash = this.jdbc.sql("SELECT client_secret FROM oauth2_registered_client WHERE id=:id").param("id", existing.client().id().toString()).query(String.class).single();
			var verifier = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			assertThat(verifier.matches(secret, hash)).isTrue();
			assertThat(verifier.matches(existing.secret(), hash)).isFalse();
			nextWindow(factor);
			var enabled = postJson(http, path + "/enable", session, changeBody(4, freshCode(factor)));
			assertThat(enabled.statusCode()).isEqualTo(200);
			assertThat((Number) JsonPath.read(enabled.body(), "$.version")).isEqualTo(5);
			assertThat(enabled.body()).doesNotContain(secret, existing.secret(), hash);
			assertThat(this.resources.findById(this.resourceId).orElseThrow().version()).isEqualTo(1);
		}
	}

	@Test
	void businessRejectionsRollBackTotpWhileNoOpsConsumeItWithoutChangingTheClient() throws Exception {
		var factor = administrator();
		var existing = this.clients.create(nativeConfiguration(), SYSTEM).client();
		var other = this.resources.create("urn:example:billing", "Billing", SYSTEM);
		UUID foreignRole = this.roles.create(other.id(), "reader", "Reader", SYSTEM).id();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String code = freshCode(factor);
			long before = lastStep(factor);
			String path = PATH + "/" + existing.id();
			assertThat(postJson(http, path + "/disable", session, changeBody(2, code)).statusCode()).isEqualTo(409);
			assertThat(postJson(http, PATH + "/" + UUID.randomUUID() + "/disable", session, changeBody(1, code)).statusCode()).isEqualTo(404);
			var invalid = configuration("Orders app"); invalid.put("allowedRoleIds", List.of(foreignRole));
			assertThat(postJson(http, PATH, session, JSON.writeValueAsString(Map.of("configuration", invalid, "code", code))).statusCode()).isEqualTo(409);
			invalid.put("resourceId", UUID.randomUUID()); invalid.put("allowedRoleIds", List.of());
			assertThat(postJson(http, PATH, session, JSON.writeValueAsString(Map.of("configuration", invalid, "code", code))).statusCode()).isEqualTo(404);
			assertThat(lastStep(factor)).isEqualTo(before);
			var noOp = postJson(http, path + "/configuration", session, JSON.writeValueAsString(Map.of("version", 1, "configuration", configuration("Orders app"), "code", code)));
			assertThat(noOp.statusCode()).isEqualTo(200);
			assertThat(lastStep(factor)).isGreaterThan(before);
			assertThat(this.clients.findById(existing.id())).contains(existing);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='client_updated'").query(Long.class).single()).isZero();
			assertThat(postJson(http, path + "/disable", session, changeBody(1, code)).statusCode()).isEqualTo(400);
			nextWindow(factor);
			assertThat(postJson(http, path + "/enable", session, changeBody(1, freshCode(factor))).statusCode()).isEqualTo(200);
			assertThat(this.clients.findById(existing.id())).contains(existing);
			this.resources.setEnabled(this.resourceId, 1, false, SYSTEM);
			nextWindow(factor);
			assertThat(postJson(http, path + "/enable", session, changeBody(1, freshCode(factor))).statusCode()).isEqualTo(409);
			assertThat(get(http, path, session).statusCode()).isEqualTo(200);
			assertThat(postJson(http, path + "/disable", session, changeBody(1, freshCode(factor))).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void everyOperationRequiresCurrentAdministratorMfaAndWritesRequireHeaderCsrf() throws Exception {
		var factor = administrator();
		var existing = this.clients.create(nativeConfiguration(), SYSTEM).client();
		UUID ordinary = this.users.create("bobby", "Bob", SYSTEM).id();
		this.setups.complete(ordinary, this.setups.issue(ordinary, SYSTEM).token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var http = client()) {
			assertThat(get(http, PATH, null).statusCode()).isEqualTo(401);
			String userSession = login(http, "bobby");
			assertThat(get(http, PATH, userSession).statusCode()).isEqualTo(403);
			assertThat(postJson(http, PATH, userSession, createBody(freshCode(factor))).statusCode()).isEqualTo(403);
			String password = login(http, "alice");
			assertThat(get(http, PATH + "/" + existing.id(), password).statusCode()).isEqualTo(403);
			String session = elevate(http, password, factor);
			String body = changeBody(1, freshCode(factor));
			for (String operation : List.of("configuration", "disable", "enable", "secret/rotate")) {
				assertThat(post(http, PATH + "/" + existing.id() + "/" + operation, session, json(body, null)).statusCode()).isEqualTo(403);
			}
			assertThat(post(http, PATH, session, json(createBody(freshCode(factor)), null)).statusCode()).isEqualTo(403);
			assertThat(post(http, PATH, session, "code=" + freshCode(factor)).statusCode()).isEqualTo(415);
			assertThat(postJson(http, PATH + "?code=000000", session, createBody(freshCode(factor))).statusCode()).isEqualTo(400);
			for (String method : List.of("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) {
				var response = http.send(HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH)).header("Cookie", session)
						.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
				assertThat(response.statusCode()).isEqualTo(403);
			}
			this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			assertThat(get(http, PATH, session).statusCode()).isEqualTo(403);
			assertThat(postJson(http, PATH, session, createBody(freshCode(factor))).statusCode()).isEqualTo(403);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "root-unknown", "root-duplicate", "root-array", "root-null", "trailing", "code-missing", "code-number", "configuration-null", "configuration-unknown", "configuration-duplicate", "configuration-missing", "name-number", "name-null", "resource-invalid", "resource-short", "resource-null", "redirect-scalar", "redirect-null", "redirect-number", "redirect-duplicate", "logout-unsupported", "logout-empty", "scope-scalar", "scope-duplicate", "scope-unknown", "role-duplicate", "role-case-duplicate", "role-invalid", "role-number", "role-null", "secret-supplied" })
	void malformedOrAmbiguousJsonCannotConsumeTotpOrCreateAnyClient(String invalid) throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String code = freshCode(factor);
			String body = invalidBody(invalid, createBody(code));
			long step = lastStep(factor);
			var result = postJson(http, PATH, session, body);
			assertThat(result.statusCode()).as(invalid).isEqualTo(400);
			assertSecurityHeaders(result);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.clients.search(null, 100, null).items()).isEmpty();
			assertThat(result.body()).doesNotContain(body, PASSWORD, factor.secret());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "0", "-1", "\"1\"", "1.0", "1e0", "true", "null", "9223372036854775808" })
	void changeVersionsRequireAPositiveLongJsonInteger(String version) throws Exception {
		var factor = administrator();
		var existing = this.clients.create(nativeConfiguration(), SYSTEM).client();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			long step = lastStep(factor);
			var result = postJson(http, PATH + "/" + existing.id() + "/disable", session, "{\"version\":" + version + ",\"code\":\"" + freshCode(factor) + "\"}");
			assertThat(result.statusCode()).isEqualTo(400);
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.clients.findById(existing.id())).contains(existing);
		}
	}

	@Test
	void boundedJsonAlsoRejectsChunkedBodiesAndUnusableIds() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String token = csrf(get(http, "/api/csrf", session));
			String oversized = createBody(freshCode(factor)) + " ".repeat(8192);
			assertThat(post(http, PATH, session, json(oversized, token)).statusCode()).isEqualTo(413);
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH)).timeout(Duration.ofSeconds(20))
					.header("Cookie", session).header("Content-Type", "application/json").header("X-CSRF-TOKEN", token)
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversized.getBytes(StandardCharsets.UTF_8)))).build();
			assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(413);
			for (String id : List.of("1-1-1-1-1", "invalid")) { assertThat(get(http, PATH + "/" + id, session).statusCode()).isEqualTo(400); }
			assertThat(get(http, PATH + "/" + UUID.randomUUID(), session).statusCode()).isEqualTo(404);
			assertThat(this.clients.search(null, 100, null).items()).isEmpty();
		}
	}

	@Test
	void unacceptableSuccessRepresentationsCannotConsumeTotpOrRotateSecrets() throws Exception {
		var factor = administrator();
		var existing = this.clients.create(nativeConfiguration(), SYSTEM);
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String token = csrf(get(http, "/api/csrf", session));
			long step = lastStep(factor);
			for (String path : List.of(PATH, PATH + "/" + existing.client().id() + "/secret/rotate")) {
				String body = path.equals(PATH) ? createBody(freshCode(factor)) : changeBody(1, freshCode(factor));
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).header("Cookie", session)
						.header("X-CSRF-TOKEN", token).header("Content-Type", "application/json").header("Accept", "text/html")
						.POST(HttpRequest.BodyPublishers.ofString(body)).build();
				assertThat(http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(406);
			}
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.clients.search(null, 100, null).items()).containsExactly(existing.client());
			String hash = this.jdbc.sql("SELECT client_secret FROM oauth2_registered_client WHERE id=:id").param("id", existing.client().id().toString()).query(String.class).single();
			assertThat(PasswordEncoderFactories.createDelegatingPasswordEncoder().matches(existing.secret(), hash)).isTrue();
		}
	}

	@Test
	void aMaximumPageOfLongNamesFitsTheBoundWithoutReturningFullConfigurations() throws Exception {
		var factor = administrator();
		var seed = this.clients.create(nativeConfiguration(), SYSTEM).client();
		String display = "\"".repeat(128);
		this.jdbc.sql("""
				WITH positions AS (SELECT gen_random_uuid()::text AS id, clock_timestamp() AS now FROM generate_series(1,100)),
				registered AS (
				    INSERT INTO oauth2_registered_client(id,client_id,client_id_issued_at,client_secret,client_name,
				        client_authentication_methods,authorization_grant_types,redirect_uris,post_logout_redirect_uris,scopes,client_settings,token_settings)
				    SELECT p.id,p.id,p.now,s.client_secret,:display,s.client_authentication_methods,s.authorization_grant_types,
				        s.redirect_uris,s.post_logout_redirect_uris,s.scopes,s.client_settings,s.token_settings
				    FROM positions p CROSS JOIN oauth2_registered_client s WHERE s.id=:seed
				    RETURNING id,client_id_issued_at
				)
				INSERT INTO iam_client(id,resource_id,created_at,updated_at,secret_rotated_at)
				SELECT id,:resource,client_id_issued_at,client_id_issued_at,client_id_issued_at FROM registered
				""").param("display", display).param("seed", seed.id().toString()).param("resource", this.resourceId).update();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			var result = get(http, PATH + "?pageSize=100", session);
			assertThat(result.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<List<Map<String, Object>>>read(result.body(), "$.items")).hasSize(100).allSatisfy(item -> assertThat(item).doesNotContainKeys("configuration", "redirectUris", "allowedRoleIds"));
			assertThat(result.body().getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(131_072);
			assertThat(JsonPath.<String>read(result.body(), "$.nextCursor")).isNotEmpty();
		}
	}

	@Test
	void paginationHasCompactItemsAndFilterBoundCursorsWithStrictQueryFields() throws Exception {
		var factor = administrator();
		for (int i = 0; i < 3; i++) { this.clients.create(nativeConfiguration(), SYSTEM); }
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			var first = get(http, PATH + "?status=ACTIVE&pageSize=2", session);
			assertThat(first.statusCode()).isEqualTo(200);
			List<String> ids = JsonPath.read(first.body(), "$.items[*].id");
			assertThat(ids).hasSize(2);
			String cursor = JsonPath.read(first.body(), "$.nextCursor");
			var last = get(http, PATH + "?status=ACTIVE&cursor=" + encode(cursor), session);
			assertThat(last.statusCode()).isEqualTo(200);
			assertThat(JsonPath.<List<String>>read(last.body(), "$.items[*].id")).hasSize(1).doesNotContainAnyElementsOf(ids);
			assertThat((Object) JsonPath.read(last.body(), "$.nextCursor")).isNull();
			assertThat(get(http, PATH + "?status=DISABLED&cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			assertThat(get(http, PATH + "?cursor=" + encode(cursor), session).statusCode()).isEqualTo(400);
			for (String query : List.of("status=active", "status=", "pageSize=0", "pageSize=101", "pageSize=01", "pageSize=1&pageSize=2", "cursor=!!!", "cursor=", "actor=other", "displayName=ignored")) {
				assertThat(get(http, PATH + "?" + query, session).statusCode()).as(query).isEqualTo(400);
			}
			assertThat(get(http, PATH + "/" + ids.getFirst() + "?version=1", session).statusCode()).isEqualTo(400);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "create:audit-error", "create:audit-suppressed", "create:audit-deferred", "create:session-error", "create:session-suppressed", "create:session-deferred", "rotate:audit-error", "rotate:audit-deferred", "rotate:session-deferred", "update:audit-deferred", "disable:session-deferred", "enable:audit-deferred" })
	void failedAuditSessionOrCommitCannotPublishSecretsOrPartlyCommitClientChanges(String scenario) throws Exception {
		var factor = administrator();
		String operation = scenario.split(":")[0];
		String fault = scenario.split(":")[1];
		var existing = operation.equals("create") ? null : this.clients.create(nativeConfiguration(), SYSTEM);
		if (operation.equals("enable")) { this.clients.setEnabled(existing.client().id(), 1, false, SYSTEM); }
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			String token = csrf(get(http, "/api/csrf", session));
			long step = lastStep(factor);
			var nativeBefore = this.jdbc.sql("SELECT to_jsonb(c)::text FROM oauth2_registered_client c ORDER BY id").query(String.class).list();
			var stateBefore = this.clients.search(null, 100, null);
			var eventsBefore = this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list();
			boolean audit = fault.startsWith("audit");
			String condition = audit ? "NEW.action LIKE 'client_%'" : "true";
			String body = fault.endsWith("suppressed") ? "RETURN NULL;" : "RAISE EXCEPTION 'test client persistence failure';";
			this.jdbc.sql("CREATE FUNCTION client_http_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN " + body + " END IF; RETURN NEW; END $$").update();
			boolean deferred = fault.endsWith("deferred");
			this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " client_http_fault " + (deferred ? "AFTER" : "BEFORE")
					+ (audit ? " INSERT ON iam_security_audit" : " UPDATE ON iam_browser_session")
					+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION client_http_fault()").update();
			String path = operation.equals("create") ? PATH : PATH + "/" + existing.client().id() + "/" + (operation.equals("rotate") ? "secret/rotate" : operation.equals("update") ? "configuration" : operation);
			String payload = switch (operation) {
				case "create" -> createBody(freshCode(factor));
				case "update" -> JSON.writeValueAsString(Map.of("version", 1, "configuration", configuration("Updated"), "code", freshCode(factor)));
				default -> changeBody(operation.equals("enable") ? 2 : 1, freshCode(factor));
			};
			var result = post(http, path, session, json(payload, token));
			assertThat(result.statusCode()).isEqualTo(503);
			assertSecurityHeaders(result);
			assertThat(result.body()).doesNotContain("secret", "configuration", "createdAt", "Updated");
			assertThat(result.headers().firstValue("Location")).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
			assertThat(this.clients.search(null, 100, null)).isEqualTo(stateBefore);
			assertThat(this.jdbc.sql("SELECT to_jsonb(c)::text FROM oauth2_registered_client c ORDER BY id").query(String.class).list()).isEqualTo(nativeBefore);
			assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a ORDER BY id").query(String.class).list()).isEqualTo(eventsBefore);
		}
	}

	@Test
	void clientTotpFailuresShareTheExistingOperationBudget() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			for (int i = 0; i < 5; i++) { assertThat(postJson(http, PATH, session, createBody("invalid")).statusCode()).isEqualTo(400); }
			assertThat(postJson(http, PATH, session, createBody(freshCode(factor))).statusCode()).isEqualTo(429);
			String form = "audience=urn:new&displayName=New&code=" + freshCode(factor) + "&_csrf=" + encode(csrf(get(http, "/api/csrf", session)));
			assertThat(post(http, "/api/admin/resources", session, form).statusCode()).isEqualTo(429);
			assertThat(this.clients.search(null, 100, null).items()).isEmpty();
		}
	}

	@Test
	void aQueuedClientWriteRechecksAdministratorMembershipBeforeCommit() throws Exception {
		var factor = administrator();
		try (var http = client(); var executor = Executors.newSingleThreadExecutor();
				var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
			String session = elevate(http, login(http, "alice"), factor);
			String token = csrf(get(http, "/api/csrf", session));
			long step = lastStep(factor);
			connection.setAutoCommit(false);
			try (var statement = connection.prepareStatement("SELECT id FROM iam_resource WHERE id=? FOR UPDATE")) { statement.setObject(1, this.resourceId); statement.executeQuery().close(); }
			var write = executor.submit(() -> post(http, PATH, session, json(createBody(freshCode(factor)), token)));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_resource WHERE id%FOR UPDATE%'").query(Long.class).single() > 0);
				// Changes current authority without contending on the actor/user lock held by the operation.
				this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", factor.userId()).update();
			}
			finally { connection.commit(); }
			var result = write.get(10, TimeUnit.SECONDS);
			assertThat(result.statusCode()).isEqualTo(503);
			assertThat(this.clients.search(null, 100, null).items()).isEmpty();
			assertThat(lastStep(factor)).isEqualTo(step);
		}
	}

	@Test
	void swaggerCoversAllOperationsTypedJsonCsrfAndOneTimeSecretResponses() throws Exception {
		var factor = administrator();
		try (var http = client()) {
			String session = elevate(http, login(http, "alice"), factor);
			var response = get(http, "/v3/api-docs", session);
			assertThat(response.statusCode()).isEqualTo(200);
			Map<String, Object> paths = JsonPath.read(response.body(), "$.paths");
			assertThat(paths).containsKeys(PATH, PATH + "/{clientId}", PATH + "/{clientId}/configuration", PATH + "/{clientId}/disable", PATH + "/{clientId}/enable", PATH + "/{clientId}/secret/rotate");
			for (String suffix : List.of("", "/{clientId}/configuration", "/{clientId}/disable", "/{clientId}/enable", "/{clientId}/secret/rotate")) {
				Map<String, Object> operation = JsonPath.read(response.body(), "$.paths['" + PATH + suffix + "'].post");
				assertThat(JsonPath.<Map<String, Object>>read(operation, "$.requestBody.content")).containsOnlyKeys("application/json");
				List<Map<String, Object>> parameters = JsonPath.read(operation, "$.parameters");
				assertThat(parameters).anySatisfy(parameter -> assertThat(parameter).containsEntry("name", "X-CSRF-TOKEN").containsEntry("in", "header").containsEntry("required", true));
				String status = suffix.isEmpty() ? "201" : "200";
				String expected = suffix.isEmpty() || suffix.endsWith("rotate") ? "IdentityClientSecretResponse" : "IdentityClientResponse";
				assertThat(JsonPath.<String>read(operation, "$.responses['" + status + "'].content['application/json'].schema['$ref']")).endsWith("/" + expected);
			}
			for (String schema : List.of("IdentityClientCreateRequest", "IdentityClientUpdateRequest", "IdentityClientChangeRequest")) {
				assertThat(JsonPath.<Boolean>read(response.body(), "$.components.schemas." + schema + ".properties.code.writeOnly")).isTrue();
				assertThat(JsonPath.<List<String>>read(response.body(), "$.components.schemas." + schema + ".required")).contains("code");
			}
			assertThat(JsonPath.<List<String>>read(response.body(), "$.components.schemas.IdentityClientConfigurationRequest.required"))
					.containsExactlyInAnyOrder("displayName", "resourceId", "redirectUris", "scopes", "allowedRoleIds");
		}
	}

	private Map<String, Object> configuration(String display) {
		var config = new LinkedHashMap<String, Object>();
		config.put("displayName", display); config.put("resourceId", this.resourceId.toString());
		config.put("redirectUris", List.of("https://orders.example/callback"));
		config.put("scopes", List.of("openid", "profile", "offline_access")); config.put("allowedRoleIds", List.of(this.roleId.toString()));
		return config;
	}
	private IdentityClientConfiguration nativeConfiguration() {
		return new IdentityClientConfiguration("Orders app", this.resourceId, List.of("https://orders.example/callback"), Set.of("openid", "profile", "offline_access"), Set.of(this.roleId));
	}
	private String createBody(String code) { return JSON.writeValueAsString(Map.of("configuration", configuration("Orders app"), "code", code)); }
	private static String changeBody(long version, String code) { return JSON.writeValueAsString(Map.of("version", version, "code", code)); }
	private HttpResponse<String> postJson(HttpClient http, String path, String session, String body) throws Exception {
		return post(http, path, session, json(body, csrf(get(http, "/api/csrf", session))));
	}
	private String invalidBody(String invalid, String body) {
		return switch (invalid) {
			case "root-unknown" -> body.substring(0, body.length() - 1) + ",\"actor\":\"other\"}";
			case "root-duplicate" -> body.substring(0, body.length() - 1) + ",\"code\":\"123456\"}";
			case "root-array" -> "[" + body + "]";
			case "root-null" -> "null";
			case "trailing" -> body + " {}";
			case "code-missing" -> JSON.writeValueAsString(Map.of("configuration", configuration("Orders app")));
			case "code-number" -> body.replaceFirst("\"code\":\"[0-9]+\"", "\"code\":123456");
			case "configuration-null" -> JSON.writeValueAsString(Map.of("code", "123456", "configuration", JSON.nullNode()));
			case "configuration-unknown" -> body.replace("\"displayName\":", "\"unknown\":1,\"displayName\":");
			case "configuration-duplicate" -> body.replace("\"displayName\":", "\"displayName\":\"Other\",\"displayName\":");
			case "configuration-missing" -> body.replace("\"displayName\":\"Orders app\",", "");
			case "name-number" -> body.replace("\"Orders app\"", "123");
			case "name-null" -> body.replace("\"Orders app\"", "null");
			case "resource-invalid" -> body.replace(this.resourceId.toString(), "invalid");
			case "resource-short" -> body.replace(this.resourceId.toString(), "1-1-1-1-1");
			case "resource-null" -> body.replace("\"" + this.resourceId + "\"", "null");
			case "redirect-scalar" -> body.replace("[\"https://orders.example/callback\"]", "\"https://orders.example/callback\"");
			case "redirect-null" -> body.replace("[\"https://orders.example/callback\"]", "null");
			case "redirect-number" -> body.replace("[\"https://orders.example/callback\"]", "[1]");
			case "redirect-duplicate" -> body.replace("[\"https://orders.example/callback\"]", "[\"https://orders.example/callback\",\"https://orders.example/callback\"]");
			case "logout-unsupported" -> body.replace("\"displayName\":", "\"postLogoutRedirectUris\":[\"https://orders.example/logout\"],\"displayName\":");
			case "logout-empty" -> body.replace("\"displayName\":", "\"postLogoutRedirectUris\":[],\"displayName\":");
			case "scope-scalar" -> body.replace("[\"openid\",\"profile\",\"offline_access\"]", "\"openid\"");
			case "scope-duplicate" -> body.replace("\"profile\"", "\"openid\"");
			case "scope-unknown" -> body.replace("\"profile\"", "\"admin\"");
			case "role-duplicate" -> body.replace("[\"" + this.roleId + "\"]", "[\"" + this.roleId + "\",\"" + this.roleId + "\"]");
			case "role-case-duplicate" -> body.replace("[\"" + this.roleId + "\"]", "[\"" + this.roleId + "\",\"" + this.roleId.toString().toUpperCase(java.util.Locale.ROOT) + "\"]");
			case "role-invalid" -> body.replace(this.roleId.toString(), "invalid");
			case "role-number" -> body.replace("[\"" + this.roleId + "\"]", "[1]");
			case "role-null" -> body.replace("[\"" + this.roleId + "\"]", "[null]");
			case "secret-supplied" -> body.substring(0, body.length() - 1) + ",\"secret\":\"chosen\"}";
			default -> throw new IllegalArgumentException(invalid);
		};
	}
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
			Path path = Files.createTempFile("iam-client-http-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }

}
