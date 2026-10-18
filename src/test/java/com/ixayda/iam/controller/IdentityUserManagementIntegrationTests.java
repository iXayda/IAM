package com.ixayda.iam.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import com.jayway.jsonpath.JsonPath;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "iam.browser.requests-per-second=1000")
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserManagementIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:user-query-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final Instant CREATED = Instant.parse("2026-10-01T08:12:35.123456Z");

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUserSetups setups;
	@Autowired private JdbcClient jdbc;
	@MockitoSpyBean private IdentityUsers users;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@Test
	void administratorQueriesReturnOnlyTheDocumentedUserFieldsAndNeverCredentials() throws Exception {
		var factor = administrator();
		var target = this.users.create("bobby", "Bob 用户", SYSTEM);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var list = get(client, "/api/admin/users", session);
			assertThat(list.statusCode()).isEqualTo(200);
			assertSecurityHeaders(list);
			Map<String, Object> body = JsonPath.read(list.body(), "$");
			assertThat(body).containsOnlyKeys("items", "nextCursor");
			List<Map<String, Object>> items = JsonPath.read(list.body(), "$.items");
			assertThat(items).hasSize(2).allSatisfy(item -> assertThat(item).containsOnlyKeys("id", "username", "displayName", "status", "createdAt"));
			var detail = get(client, "/api/admin/users/" + target.id().toString().toUpperCase(java.util.Locale.ROOT), session);
			assertThat(detail.statusCode()).isEqualTo(200);
			assertSecurityHeaders(detail);
			Map<String, Object> user = JsonPath.read(detail.body(), "$");
			assertThat(user).containsOnlyKeys("id", "username", "displayName", "status", "createdAt")
					.containsEntry("id", target.id().toString()).containsEntry("username", "bobby").containsEntry("displayName", "Bob 用户").containsEntry("status", "PENDING");
			assertThat(list.body() + detail.body()).doesNotContain(PASSWORD, factor.secret(), "password_hash", "credentialVersion", "factorId");
			assertThat(events("admin_access_denied")).isZero();
		}
	}

	@Test
	void defaultAndMaximumPageSizesAreBoundedAndTheLastPageHasNoContinuation() throws Exception {
		var factor = administrator();
		for (int i = 1; i <= 102; i++) { seed(new UUID(0, i), "user-" + i, "Needle" + "😀".repeat(122), "pending", CREATED); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var first = get(client, "/api/admin/users?keyword=Needle", session);
			assertThat(first.statusCode()).isEqualTo(200);
			assertThat(ids(first)).hasSize(20);
			var large = get(client, "/api/admin/users?keyword=Needle&pageSize=100", session);
			assertThat(ids(large)).hasSize(100);
			String cursor = JsonPath.read(large.body(), "$.nextCursor");
			var last = get(client, "/api/admin/users?keyword=Needle&pageSize=2&cursor=" + encode(cursor), session);
			assertThat(ids(last)).containsExactly(new UUID(0, 101).toString(), new UUID(0, 102).toString());
			assertThat((Object) JsonPath.read(last.body(), "$.nextCursor")).isNull();
			var empty = get(client, "/api/admin/users?keyword=absent", session);
			assertThat(ids(empty)).isEmpty();
			assertThat((Object) JsonPath.read(empty.body(), "$.nextCursor")).isNull();
		}
	}

	@Test
	void cursorsPreserveUnicodeFiltersMicrosecondTimeAndPostgresqlUuidOrderAcrossPages() throws Exception {
		var factor = administrator();
		List<UUID> expected = List.of(UUID.fromString("00000000-0000-0000-0000-000000000001"),
				UUID.fromString("7fffffff-ffff-ffff-ffff-ffffffffffff"), UUID.fromString("80000000-0000-0000-0000-000000000000"),
				UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"), new UUID(0, 5));
		for (int i = 0; i < expected.size(); i++) { seed(expected.get(i), "match-" + i, "Café 用户 😀", "pending", i == 4 ? CREATED.plusNanos(1000) : CREATED); }
		seed(new UUID(0, 6), "excluded", "Café 用户 😀", "disabled", CREATED);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String cursor = null;
			var found = new ArrayList<String>();
			do {
				String path = "/api/admin/users?status=PENDING&pageSize=2&keyword=" + encode("Cafe\u0301 用户 😀") + (cursor == null ? "" : "&cursor=" + encode(cursor));
				var page = get(client, path, session);
				assertThat(page.statusCode()).isEqualTo(200);
				found.addAll(ids(page));
				cursor = JsonPath.read(page.body(), "$.nextCursor");
				assertThat(found).hasSizeLessThanOrEqualTo(5);
			} while (cursor != null);
			assertThat(found).containsExactlyElementsOf(expected.stream().map(UUID::toString).toList());
			String first = JsonPath.read(get(client, "/api/admin/users?keyword=" + encode("Café 用户 😀") + "&status=PENDING&pageSize=1", session).body(), "$.nextCursor");
			for (String query : List.of("keyword=Other&status=PENDING", "keyword=" + encode("Café 用户 😀") + "&status=DISABLED", "keyword=" + encode("Café 用户 😀"))) {
				assertInvalid(get(client, "/api/admin/users?" + query + "&cursor=" + encode(first), session));
			}
		}
	}

	@ParameterizedTest
	@CsvSource({ "ALIAS, active", "%, pending", "_, disabled" })
	void searchesLiteralSubstringsAndCombinesThemWithStatus(String keyword, String state) throws Exception {
		var factor = administrator();
		UUID target = new UUID(0, 1);
		seed(target, "alias-target", "Percent % Under_score", state, CREATED);
		seed(new UUID(0, 2), "different", "Other", "pending", CREATED);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var page = get(client, "/api/admin/users?keyword=" + encode(keyword) + "&status=" + state.toUpperCase(java.util.Locale.ROOT), session);
			assertThat(page.statusCode()).isEqualTo(200);
			assertThat(ids(page)).containsExactly(target.toString());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "pageSize=0", "pageSize=101", "pageSize=-1", "pageSize=2147483648", "pageSize=x", "pageSize=", "pageSize=1&pageSize=2",
			"status=active", "status=UNKNOWN", "status=", "status=%20ACTIVE%20", "status=ACTIVE&status=PENDING",
			"keyword=%20%20", "keyword=%00", "keyword=one&keyword=two", "sort=id", "userId=00000000-0000-0000-0000-000000000001", "cursor=", "cursor=!!!" })
	void rejectsInvalidRepeatedAndUnknownSearchParameters(String query) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, "/api/admin/users?" + query, session));
			assertInvalid(get(client, "/api/admin/users?keyword=" + "a".repeat(129), session));
		}
	}

	@ParameterizedTest
	@MethodSource("invalidCursors")
	void malformedCursorsReturnClientErrorsWithoutReachingDatabaseTimestampConversion(String cursor) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, "/api/admin/users?cursor=" + encode(cursor), session));
		}
	}

	static Stream<String> invalidCursors() {
		String id = "00000000-0000-0000-0000-000000000001";
		return Stream.concat(Stream.of("a".repeat(1025), Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] { (byte) 0xff }),
				Base64.getUrlEncoder().encodeToString(("2026-10-01T00:00:00Z\n" + id + "\n\nxx").getBytes(java.nio.charset.StandardCharsets.UTF_8))),
				Stream.of("garbage", "2026-10-01T00:00:00Z\n" + id + "\n\n\nextra", "not-a-date\n" + id + "\n\n",
						"+999999999-01-01T00:00:00Z\n" + id + "\n\n", "-4713-01-01T00:00:00Z\n" + id + "\n\n",
						"2026-10-01T00:00:00.000000001Z\n" + id + "\n\n", "2026-10-01T00:00:00Z\n1-1-1-1-1\n\n",
						"2026-10-01T00:00:00Z\n" + id + "\ninvalid\n")
						.map(value -> Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
	}

	@Test
	void headersCannotSupplyMissingSearchFieldsAndDetailEndpointsAcceptNoQueryParameters() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/admin/users"))
					.header("Cookie", session).header("keyword", "absent").header("status", "INVALID").header("page-Size", "0").header("cursor", "!!!").GET().build();
			var response = client.send(request, HttpResponse.BodyHandlers.ofString());
			assertThat(response.statusCode()).isEqualTo(200);
			assertThat(ids(response)).containsExactly(factor.userId().toString());
			assertInvalid(get(client, "/api/admin/users/" + factor.userId() + "?keyword=alice", session));
			var body = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/api/admin/users"))
					.header("Cookie", session).method("GET", HttpRequest.BodyPublishers.ofString("keyword=absent")).build();
			assertInvalid(client.send(body, HttpResponse.BodyHandlers.ofString()));
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "not-a-uuid", "1-1-1-1-1", "00000000-0000-0000-0000-00000000000g" })
	void malformedUserIdsReturn400AndWellFormedUnknownIdsReturn404(String id) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, "/api/admin/users/" + id, session));
			var absent = get(client, "/api/admin/users/" + UUID.randomUUID(), session);
			assertThat(absent.statusCode()).isEqualTo(404);
			assertSecurityHeaders(absent);
		}
	}

	@Test
	void anonymousOrdinaryAndPasswordOnlyAdministratorRequestsCannotListOrInspectUsers() throws Exception {
		var factor = administrator();
		var ordinary = this.users.create("bobby", "Bob", SYSTEM);
		var proof = this.setups.issue(ordinary.id(), SYSTEM);
		this.setups.complete(ordinary.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var client = client()) {
			String administrator = login(client, "alice");
			String user = login(client, "bobby");
			for (String path : List.of("/api/admin/users", "/api/admin/users/" + factor.userId(), "/api/admin/users/not-a-uuid", "/api/admin/users?sort=secret")) {
				assertThat(get(client, path, null).statusCode()).isEqualTo(401);
				assertThat(get(client, path, user).statusCode()).isEqualTo(403);
				assertThat(get(client, path, administrator).statusCode()).isEqualTo(403);
			}
			assertThat(events("admin_access_denied")).isEqualTo(12);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" })
	void onlyTheTwoExactGetRoutesAreAuthorized(String method) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			for (String path : List.of("/api/admin/users", "/api/admin/users/" + factor.userId())) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).header("Cookie", session)
						.header("X-CSRF-TOKEN", token).method(method, HttpRequest.BodyPublishers.noBody()).build();
				assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			}
			assertThat(get(client, "/api/admin/users/" + factor.userId() + "/password", session).statusCode()).isEqualTo(403);
		}
	}

	@ParameterizedTest
	@CsvSource({ "membership, 403", "mfa-expiry, 403", "password-expiry, 401", "credential-version, 401", "logout, 401" })
	void currentMembershipMfaAndPasswordSessionStateAreRequiredForEveryQuery(String operation, int expected) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			if (operation.equals("membership")) { this.jdbc.sql("DELETE FROM iam_administrator").update(); }
			else if (operation.equals("mfa-expiry")) {
				long passwordTime = Instant.now().minusSeconds(1200).toEpochMilli();
				replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, passwordTime);
				long version = this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id = :id").param("id", factor.userId()).query(Long.class).single();
				replaceAttribute(session, IdentityAdministratorSessions.AUTHENTICATION, new IdentityAdministratorAuthentication(factor.userId(), factor.factorId(), version, passwordTime, Instant.now().minusSeconds(901)));
			}
			else if (operation.equals("password-expiry")) { replaceAttribute(session, IdentityBrowserSessions.AUTHENTICATED_AT, Instant.now().minusSeconds(28801).toEpochMilli()); }
			else if (operation.equals("credential-version")) { this.jdbc.sql("UPDATE iam_password SET credential_version = credential_version + 1 WHERE user_id = :id").param("id", factor.userId()).update(); }
			else { assertThat(post(client, "/logout", session, "_csrf=" + encode(csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(204); }
			for (String path : List.of("/api/admin/users", "/api/admin/users/" + factor.userId())) {
				assertThat(get(client, path, session).statusCode()).isEqualTo(expected);
			}
			assertThat(events("admin_access_denied")).isEqualTo(2);
		}
	}

	@ParameterizedTest
	@CsvSource({ "error, list", "silent, list", "error, detail", "silent, detail" })
	void unavailableDenialAuditingNeverReturnsUserData(String mode, String endpoint) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			this.jdbc.sql("CREATE FUNCTION user_query_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'admin_access_denied' THEN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected query denial audit failure';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql("CREATE TRIGGER user_query_denial_fault BEFORE INSERT ON iam_security_audit FOR EACH ROW EXECUTE FUNCTION user_query_denial_fault()").update();
			try { assertUnavailable(get(client, endpoint.equals("list") ? "/api/admin/users" : "/api/admin/users/" + factor.userId(), session)); }
			finally { this.jdbc.sql("DROP FUNCTION user_query_denial_fault() CASCADE").update(); }
			assertThat(events("admin_access_denied")).isZero();
		}
	}

	@ParameterizedTest
	@CsvSource({ "error, list", "silent, list", "error, detail", "silent, detail" })
	void sessionPersistenceFailuresDiscardAlreadyProducedUserResponses(String mode, String endpoint) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			this.jdbc.sql("CREATE FUNCTION user_query_session_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected query session failure';") + " END $$").update();
			this.jdbc.sql("CREATE TRIGGER user_query_session_fault BEFORE UPDATE ON iam_browser_session FOR EACH ROW EXECUTE FUNCTION user_query_session_fault()").update();
			try { assertUnavailable(get(client, endpoint.equals("list") ? "/api/admin/users" : "/api/admin/users/" + factor.userId(), session)); }
			finally { this.jdbc.sql("DROP FUNCTION user_query_session_fault() CASCADE").update(); }
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "list", "detail" })
	void queryStorageFailuresReturn503WithoutDatabaseOrCredentialDetails(String endpoint) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var failure = new DataAccessResourceFailureException("Sensitive SQL and connection details");
			if (endpoint.equals("list")) { doThrow(failure).when(this.users).search(any(), any(), anyInt(), any()); }
			else { doThrow(failure).when(this.users).findById(factor.userId()); }
			assertUnavailable(get(client, endpoint.equals("list") ? "/api/admin/users" : "/api/admin/users/" + factor.userId(), session));
		}
	}

	private IdentityTotpEnrollment administrator() {
		UUID userId = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = this.administrators.prepareCandidate(userId, PASSWORD, context()).orElseThrow().enrollment().orElseThrow();
		this.administrators.bootstrap(userId, factor.factorId(), PASSWORD, otp(factor), context()).orElseThrow();
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
		var response = post(client, "/admin/mfa", session, "code=" + otp(factor) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", session))));
		assertThat(response.statusCode()).isEqualTo(204);
		return cookie(response);
	}

	private void seed(UUID id, String username, String displayName, String status, Instant createdAt) {
		this.jdbc.sql("INSERT INTO iam_user(id, username, display_name, status, created_at) VALUES (:id, :username, :displayName, :status, :createdAt)")
				.param("id", id).param("username", username).param("displayName", displayName).param("status", status)
				.param("createdAt", OffsetDateTime.ofInstant(createdAt, ZoneOffset.UTC)).update();
	}

	private void replaceAttribute(String cookie, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update();
	}

	private static List<String> ids(HttpResponse<String> response) { return JsonPath.read(response.body(), "$.items[*].id"); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single(); }
	private static void assertInvalid(HttpResponse<String> response) {
		assertThat(response.statusCode()).isEqualTo(400);
		assertThat(response.body()).isEqualTo("Invalid user query");
		assertSecurityHeaders(response);
	}
	private static void assertUnavailable(HttpResponse<String> response) {
		assertThat(response.statusCode()).isEqualTo(503);
		assertThat(response.body()).contains("SERVICE_UNAVAILABLE");
		assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Location")).isEmpty();
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-user-query-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String otp(IdentityTotpEnrollment factor) {
		long step = Math.floorDiv(Instant.now().getEpochSecond(), 30);
		byte[] counter = new byte[8]; for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(factor.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(java.util.Locale.ROOT, "%06d", number % 1_000_000);
	}

}
