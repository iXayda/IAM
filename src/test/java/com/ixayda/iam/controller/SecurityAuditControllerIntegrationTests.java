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
import com.ixayda.iam.service.SecurityAudits;

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
class SecurityAuditControllerIntegrationTests extends BrowserHttpTestSupport {

	private static final String PATH = "/api/admin/audits";
	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:audit-query-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	private static final Instant RECORDED = Instant.parse("2026-10-01T08:12:35.123456Z");
	private static final String SOURCE = "internal:seed";

	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUsers users;
	@Autowired private JdbcClient jdbc;
	@MockitoSpyBean private SecurityAudits audits;

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
	void queryReturnsOnlyDocumentedEventMetadataAndPreservesNullTargetsWithoutLeakingSecrets() throws Exception {
		var factor = administrator();
		UUID event = UUID.randomUUID(), correlation = UUID.randomUUID();
		seed(event, "password_recovery_throttled", "failure", null, "anonymous", SOURCE, correlation, RECORDED);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = get(client, PATH + "?source=" + SOURCE, session);
			assertThat(response.statusCode()).isEqualTo(200);
			assertSecurityHeaders(response);
			Map<String, Object> body = JsonPath.read(response.body(), "$");
			assertThat(body).containsOnlyKeys("items", "nextCursor");
			List<Map<String, Object>> items = JsonPath.read(response.body(), "$.items");
			assertThat(items).singleElement().satisfies(item -> assertThat(item)
					.containsOnlyKeys("id", "action", "outcome", "targetUserId", "actor", "source", "correlationId", "recordedAt")
					.containsEntry("id", event.toString()).containsEntry("action", "PASSWORD_RECOVERY_THROTTLED")
					.containsEntry("outcome", "FAILURE").containsEntry("targetUserId", null).containsEntry("actor", "anonymous")
					.containsEntry("source", SOURCE).containsEntry("correlationId", correlation.toString()).containsEntry("recordedAt", RECORDED.toString()));
			assertThat((Object) JsonPath.read(response.body(), "$.nextCursor")).isNull();
			assertThat(response.body()).doesNotContain(PASSWORD, factor.secret(), factor.factorId().toString(), "password_hash", "credentialVersion", "secret", "token");
			assertThat(events("admin_access_denied")).isZero();
		}
	}

	@Test
	void defaultAndMaximumPagesAreBoundedAndEmptyOrLastPagesHaveNoContinuation() throws Exception {
		var factor = administrator();
		for (int i = 1; i <= 102; i++) { seed(new UUID(0, i), RECORDED); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var first = get(client, PATH + "?source=" + SOURCE, session);
			assertThat(first.statusCode()).isEqualTo(200);
			assertThat(ids(first)).hasSize(20);
			var large = get(client, PATH + "?source=" + SOURCE + "&pageSize=100", session);
			assertThat(ids(large)).hasSize(100);
			String cursor = JsonPath.read(large.body(), "$.nextCursor");
			var last = get(client, PATH + "?source=" + SOURCE + "&pageSize=2&cursor=" + encode(cursor), session);
			assertThat(ids(last)).containsExactly(new UUID(0, 2).toString(), new UUID(0, 1).toString());
			assertThat((Object) JsonPath.read(last.body(), "$.nextCursor")).isNull();
			var empty = get(client, PATH + "?source=internal:absent", session);
			assertThat(ids(empty)).isEmpty();
			assertThat((Object) JsonPath.read(empty.body(), "$.nextCursor")).isNull();
		}
	}

	@Test
	void cursorsRetainMicrosecondTimeAndDescendingPostgresqlUuidOrderWhileNewEventsAreAppended() throws Exception {
		var factor = administrator();
		List<UUID> expected = List.of(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"),
				UUID.fromString("80000000-0000-0000-0000-000000000000"), UUID.fromString("7fffffff-ffff-ffff-ffff-ffffffffffff"),
				new UUID(0, 1), new UUID(0, 5));
		for (int i = 0; i < expected.size(); i++) { seed(expected.get(i), i == 4 ? RECORDED.minusNanos(1000) : RECORDED); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String cursor = null;
			var found = new ArrayList<String>();
			do {
				var page = get(client, PATH + "?source=" + SOURCE + "&pageSize=2" + (cursor == null ? "" : "&cursor=" + encode(cursor)), session);
				assertThat(page.statusCode()).isEqualTo(200);
				found.addAll(ids(page));
				cursor = JsonPath.read(page.body(), "$.nextCursor");
				seed(UUID.randomUUID(), RECORDED.plusSeconds(1));
				assertThat(found).hasSizeLessThanOrEqualTo(5);
			} while (cursor != null);
			assertThat(found).containsExactlyElementsOf(expected.stream().map(UUID::toString).toList());
		}
	}

	@Test
	void everyFilterIsAppliedTogetherAndCursorRetainsAllCriteria() throws Exception {
		var factor = administrator();
		UUID target = UUID.randomUUID(), correlation = UUID.randomUUID();
		String actor = "user:" + target;
		for (int i = 1; i <= 3; i++) { seed(new UUID(0, i), "password_changed", "success", target, actor, SOURCE, correlation, RECORDED); }
		seed(UUID.randomUUID(), "password_changed", "success", UUID.randomUUID(), actor, SOURCE, correlation, RECORDED);
		seed(UUID.randomUUID(), "password_changed", "success", target, "system:other", SOURCE, correlation, RECORDED);
		seed(UUID.randomUUID(), "password_changed", "success", target, actor, "internal:other", correlation, RECORDED);
		seed(UUID.randomUUID(), "password_changed", "success", target, actor, SOURCE, UUID.randomUUID(), RECORDED);
		seed(UUID.randomUUID(), "password_change_failed", "failure", target, actor, SOURCE, correlation, RECORDED);
		seed(UUID.randomUUID(), "password_changed", "success", target, actor, SOURCE, correlation, RECORDED.plusSeconds(1));
		String query = "from=" + encode(RECORDED.toString()) + "&until=" + encode(RECORDED.plusSeconds(1).toString())
				+ "&action=PASSWORD_CHANGED&outcome=SUCCESS&actor=" + actor + "&source=" + SOURCE
				+ "&targetUserId=" + target + "&correlationId=" + correlation;
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var first = get(client, PATH + "?" + query + "&pageSize=1", session);
			assertThat(first.statusCode()).isEqualTo(200);
			assertThat(ids(first)).containsExactly(new UUID(0, 3).toString());
			String cursor = JsonPath.read(first.body(), "$.nextCursor");
			var second = get(client, PATH + "?" + query + "&pageSize=2&cursor=" + encode(cursor), session);
			assertThat(ids(second)).containsExactly(new UUID(0, 2).toString(), new UUID(0, 1).toString());
			assertThat((Object) JsonPath.read(second.body(), "$.nextCursor")).isNull();
			for (String changed : List.of(query.replace("from=" + encode(RECORDED.toString()), "from=" + encode(RECORDED.minusSeconds(1).toString())),
					query.replace("until=" + encode(RECORDED.plusSeconds(1).toString()), "until=" + encode(RECORDED.plusSeconds(2).toString())),
					query.replace("PASSWORD_CHANGED", "PASSWORD_RECOVERY_COMPLETED"), query.replace("SUCCESS", "FAILURE"),
					query.replace(actor, "system:other"), query.replace(SOURCE, "internal:other"),
					query.replace("targetUserId=" + target, "targetUserId=" + UUID.randomUUID()),
					query.replace("correlationId=" + correlation, "correlationId=" + UUID.randomUUID()), "")) {
				assertInvalid(get(client, PATH + "?" + changed + (changed.isEmpty() ? "" : "&") + "cursor=" + encode(cursor), session));
			}
			String equivalent = query.replace("targetUserId=" + target, "targetUserId=" + target.toString().toUpperCase(java.util.Locale.ROOT))
					.replace("correlationId=" + correlation, "correlationId=" + correlation.toString().toUpperCase(java.util.Locale.ROOT));
			assertThat(ids(get(client, PATH + "?" + equivalent + "&pageSize=2&cursor=" + encode(cursor), session))).hasSize(2);
		}
	}

	@Test
	void timeBoundsRetainNanosecondSemanticsAndAcceptEquivalentOffsets() throws Exception {
		var factor = administrator();
		for (int i = 1; i <= 3; i++) { seed(new UUID(0, i), RECORDED.plusNanos((i - 1) * 1000)); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var from = get(client, PATH + "?source=" + SOURCE + "&from=" + encode(RECORDED.plusNanos(1).toString()), session);
			assertThat(ids(from)).containsExactly(new UUID(0, 3).toString(), new UUID(0, 2).toString());
			var until = get(client, PATH + "?source=" + SOURCE + "&until=" + encode(RECORDED.plusNanos(1).toString()), session);
			assertThat(ids(until)).containsExactly(new UUID(0, 1).toString());
			String offset = OffsetDateTime.ofInstant(RECORDED, ZoneOffset.ofHours(8)).toString();
			assertThat(ids(get(client, PATH + "?source=" + SOURCE + "&from=" + encode(offset) + "&until=" + encode(RECORDED.plusNanos(1000).toString()), session)))
					.containsExactly(new UUID(0, 1).toString());
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "from=", "until=", "from=garbage", "from=2026-10-01", "from=2026-10-01T00:00:00", "from=2026-10-01T00:00:00Z&until=2026-10-01T00:00:00Z",
			"from=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z", "from=-4713-01-01T00:00:00Z", "until=%2B294277-01-01T00:00:00Z",
			"action=", "action=password_changed", "action=UNKNOWN", "action=%20PASSWORD_CHANGED%20", "outcome=", "outcome=success", "outcome=UNKNOWN", "outcome=%20SUCCESS%20",
			"targetUserId=", "targetUserId=invalid", "targetUserId=1-1-1-1-1", "correlationId=", "correlationId=1-1-1-1-1", "correlationId=%2000000000-0000-0000-0000-000000000001",
			"actor=", "actor=%20anonymous", "actor=bad%0Avalue", "source=", "source=bad%00value", "source=bad%25value",
			"pageSize=0", "pageSize=101", "pageSize=-1", "pageSize=2147483648", "pageSize=x", "pageSize=", "pageSize=1&pageSize=2",
			"actor=one&actor=two", "from=one&from=two", "outcome=SUCCESS&outcome=FAILURE", "sort=id", "code=123456", "cursor=", "cursor=!!!" })
	void invalidEmptyRepeatedAndUnknownQueryParametersAreRejected(String query) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, PATH + "?" + query, session));
		}
	}

	@Test
	void metadataLengthsAreBoundedAndContradictoryActionOutcomeFiltersSimplyReturnNoMatches() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, PATH + "?actor=" + "a".repeat(129), session));
			assertInvalid(get(client, PATH + "?source=" + "s".repeat(65), session));
			assertThat(ids(get(client, PATH + "?action=PASSWORD_CHANGED&outcome=FAILURE", session))).isEmpty();
		}
	}

	@ParameterizedTest
	@MethodSource("invalidCursors")
	void invalidCursorEncodingVersionIdentifiersAndTimestampPrecisionAreRejected(String cursor) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertInvalid(get(client, PATH + "?cursor=" + encode(cursor), session));
		}
	}

	static Stream<String> invalidCursors() {
		String id = "00000000-0000-0000-0000-000000000001";
		String valid = "1\n2026-10-01T00:00:00Z\n" + id + "\n\n\n\n\n\n\n\n";
		var raw = Stream.of("2" + valid.substring(1), valid + "\nextra", valid.replace("2026-10-01T00:00:00Z", "not-a-date"),
				valid.replace("2026-10-01T00:00:00Z", "+999999999-01-01T00:00:00Z"), valid.replace("2026-10-01T00:00:00Z", "2026-10-01T00:00:00.000000001Z"),
				valid.replace(id, "1-1-1-1-1"), "1\n2026-10-01T00:00:00Z\n" + id + "\n\n\nUNKNOWN\n\n\n\n\n");
		return Stream.concat(Stream.of("a".repeat(1025), Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] { (byte) 0xff }),
				Base64.getUrlEncoder().encodeToString(valid.getBytes(java.nio.charset.StandardCharsets.UTF_8))),
				raw.map(value -> Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
	}

	@Test
	void headersNeverSupplyQueryFieldsAndGetBodiesIncludingChunkedBodiesAreRejected() throws Exception {
		var factor = administrator();
		seed(new UUID(0, 1), RECORDED);
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var headers = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH + "?source=" + SOURCE)).header("Cookie", session)
					.header("action", "UNKNOWN").header("outcome", "UNKNOWN").header("from", "bad").header("target-User-Id", "bad")
					.header("page-Size", "0").header("cursor", "!!!").GET().build();
			assertThat(ids(client.send(headers, HttpResponse.BodyHandlers.ofString()))).containsExactly(new UUID(0, 1).toString());
			for (var body : List.of(HttpRequest.BodyPublishers.ofString("actor=anonymous"),
					HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream("actor=anonymous".getBytes(java.nio.charset.StandardCharsets.UTF_8))))) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH)).header("Cookie", session)
						.header("Content-Type", "application/x-www-form-urlencoded").method("GET", body).build();
				assertInvalid(client.send(request, HttpResponse.BodyHandlers.ofString()));
			}
		}
	}

	@Test
	void anonymousOrdinaryAndPasswordOnlyAdministratorsCannotReadEvenWithAnOtherwiseInvalidQuery() throws Exception {
		var factor = administrator();
		var ordinary = this.users.create("bobby", "Bob", SYSTEM);
		var proof = this.setups.issue(ordinary.id(), SYSTEM);
		this.setups.complete(ordinary.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID());
		try (var client = client()) {
			String administrator = login(client, "alice"), user = login(client, "bobby");
			for (String path : List.of(PATH, PATH + "?sort=secret")) {
				assertThat(get(client, path, null).statusCode()).isEqualTo(401);
				assertThat(get(client, path, user).statusCode()).isEqualTo(403);
				assertThat(get(client, path, administrator).statusCode()).isEqualTo(403);
			}
			assertThat(events("admin_access_denied")).isEqualTo(6);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" })
	void onlyGetIsExposedAndUnopenedSubpathsRemainDenied(String method) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			String token = csrf(get(client, "/api/csrf", session));
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + PATH)).header("Cookie", session)
					.header("X-CSRF-TOKEN", token).method(method, HttpRequest.BodyPublishers.noBody()).build();
			assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(403);
			assertThat(get(client, PATH + "/" + UUID.randomUUID(), session).statusCode()).isEqualTo(403);
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
			assertThat(get(client, PATH, session).statusCode()).isEqualTo(expected);
			assertThat(events("admin_access_denied")).isEqualTo(1);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void unavailableDenialAuditingNeverReturnsAuditData(String mode) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = login(client, "alice");
			this.jdbc.sql("CREATE FUNCTION audit_query_denial_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'admin_access_denied' THEN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected query denial audit failure';") + " END IF; RETURN NEW; END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER audit_query_denial_fault AFTER INSERT ON iam_security_audit DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER audit_query_denial_fault BEFORE INSERT ON iam_security_audit") + " FOR EACH ROW EXECUTE FUNCTION audit_query_denial_fault()").update();
			try { assertUnavailable(get(client, PATH, session)); }
			finally { this.jdbc.sql("DROP FUNCTION audit_query_denial_fault() CASCADE").update(); }
			assertThat(events("admin_access_denied")).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "error", "silent", "deferred" })
	void sessionPersistenceFailuresDiscardAlreadyProducedAuditResponses(String mode) throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			this.jdbc.sql("CREATE FUNCTION audit_query_session_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
					+ (mode.equals("silent") ? "RETURN NULL;" : "RAISE EXCEPTION 'injected query session failure';") + " END $$").update();
			this.jdbc.sql((mode.equals("deferred") ? "CREATE CONSTRAINT TRIGGER audit_query_session_fault AFTER UPDATE ON iam_browser_session DEFERRABLE INITIALLY DEFERRED" : "CREATE TRIGGER audit_query_session_fault BEFORE UPDATE ON iam_browser_session") + " FOR EACH ROW EXECUTE FUNCTION audit_query_session_fault()").update();
			try { assertUnavailable(get(client, PATH, session)); }
			finally { this.jdbc.sql("DROP FUNCTION audit_query_session_fault() CASCADE").update(); }
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void queryStorageFailuresReturn503WithoutDatabaseOrCredentialDetails() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			doThrow(new DataAccessResourceFailureException("Sensitive SQL and connection details")).when(this.audits).search(any(), anyInt(), any());
			var response = get(client, PATH, session);
			assertUnavailable(response);
			assertThat(response.body()).doesNotContain("Sensitive", "SQL", "connection", PASSWORD, factor.secret());
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

	private void seed(UUID id, Instant recordedAt) {
		seed(id, "password_auth_failed", "failure", null, "anonymous", SOURCE, UUID.randomUUID(), recordedAt);
	}

	private void seed(UUID id, String action, String outcome, UUID target, String actor, String source, UUID correlation, Instant recordedAt) {
		this.jdbc.sql("INSERT INTO iam_security_audit(id,action,outcome,target_user_id,actor,source,correlation_id,recorded_at) VALUES (:id,:action,:outcome,:target,:actor,:source,:correlation,:time)")
				.param("id", id).param("action", action).param("outcome", outcome).param("target", target).param("actor", actor)
				.param("source", source).param("correlation", correlation).param("time", OffsetDateTime.ofInstant(recordedAt, ZoneOffset.UTC)).update();
	}

	private void replaceAttribute(String cookie, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes a SET attribute_bytes = :value FROM iam_browser_session s WHERE s.primary_id = a.session_primary_id AND s.session_id = :id AND a.attribute_name = :name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).param("value", SerializationUtils.serialize(value)).update();
	}

	private static List<String> ids(HttpResponse<String> response) { return JsonPath.read(response.body(), "$.items[*].id"); }
	private long events(String action) { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = :action").param("action", action).query(Long.class).single(); }
	private static void assertInvalid(HttpResponse<String> response) {
		assertThat(response.statusCode()).isEqualTo(400);
		assertThat(response.body()).isEqualTo("Invalid audit query");
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
			Path path = Files.createTempFile("iam-audit-query-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
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
