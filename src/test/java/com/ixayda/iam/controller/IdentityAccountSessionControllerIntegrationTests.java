package com.ixayda.iam.controller;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.security.IdentityAccessTokenVerifier;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;
import com.ixayda.iam.service.IdentityAccountSessions;
import com.ixayda.iam.service.IdentityAccessTokens;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.SerializationUtils;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityAccountSessionControllerIntegrationTests extends IdentityProtocolTestSupport {

	private static final String ENDPOINT = "/api/me/sessions";
	private static final JsonMapper JSON = new JsonMapper();
	@LocalServerPort private int port;
	@Autowired private IdentityAccountSessions management;
	@Autowired private IdentityAccessTokens access;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true); registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@AfterEach
	void removeSessionFault() { this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON iam_browser_session").update(); }

	@Test
	void ownerOnlyPagingExposesManagementIdsAndTimesWithoutCookieOrAttributeData() throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); String foreign = browserSession(activeUser("bobby"), this.authenticatedAt);
		this.jdbc.sql("UPDATE iam_browser_session SET creation_time=(SELECT creation_time FROM iam_browser_session WHERE session_id=:source) WHERE session_id=:other")
				.param("source", this.sessionId).param("other", other).update();
		var ordered = java.util.stream.Stream.of(publicId(this.sessionId), publicId(other)).map(UUID::toString).sorted().toList();
		var anonymous = this.store.createSession(); this.store.save(anonymous);
		var first = success(get(ENDPOINT + "?pageSize=1")); var current = first.path("items").get(0);
		assertThat(first.path("items").size()).isEqualTo(1); assertThat(current.path("id").asText()).isEqualTo(ordered.getFirst());
		assertThat(current.path("current").asBoolean()).isEqualTo(ordered.getFirst().equals(publicId(this.sessionId).toString()));
		assertThat(current.propertyNames()).containsExactlyInAnyOrder("id", "createdAt", "authenticatedAt", "lastAccessedAt", "idleExpiresAt", "absoluteExpiresAt", "current");
		assertThat(Instant.parse(current.path("absoluteExpiresAt").asText())).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt).plusSeconds(28800));
		String cursor = first.path("nextCursor").asText(); var last = success(get(ENDPOINT + "?pageSize=1&cursor=" + encode(cursor)));
		assertThat(last.path("items").size()).isEqualTo(1); assertThat(last.path("items").get(0).path("id").asText()).isEqualTo(ordered.getLast());
		assertThat(last.path("items").get(0).path("current").asBoolean()).isEqualTo(ordered.getLast().equals(publicId(this.sessionId).toString())); assertThat(last.path("nextCursor").isNull()).isTrue();
		assertThat(first.toString() + last).doesNotContain(this.sessionId, other, foreign, anonymous.getId(), "attribute", "SECURITY_CONTEXT", "ROLE_IAM_ADMIN");
	}

	@Test
	void staleAndIdleExpiredSessionsAreExcludedAndAbsoluteExpiryCannotStallTheCursor() throws Exception {
		String idle = browserSession(this.userId, this.authenticatedAt); String stale = browserSession(this.userId, this.authenticatedAt);
		String expired = browserSession(this.userId, System.currentTimeMillis() - 28800_001); String future = browserSession(this.userId, System.currentTimeMillis() + 3_600_000);
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", idle).update(); attribute(stale, "iam.credentialVersion", 2L);
		String path = ENDPOINT + "?pageSize=1"; var ids = new java.util.ArrayList<String>(); int pages = 0;
		while (true) {
			var page = success(get(path)); pages++; for (var item : page.path("items")) { ids.add(item.path("id").asText()); }
			if (page.path("nextCursor").isNull()) { break; } path=ENDPOINT + "?pageSize=1&cursor=" + encode(page.path("nextCursor").asText());
			assertThat(pages).isLessThan(5);
		}
		assertThat(ids).containsExactly(publicId(this.sessionId).toString()); assertThat(pages).isEqualTo(3);
		assertThat(this.store.findById(expired)).isNotNull(); assertThat(this.store.findById(future)).isNotNull();
	}

	@Test
	void stableManagementIdRevokesTheCurrentCookieAfterItsRotationWhilePreservingTheCallingBrowser() throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); UUID id = publicId(other); var session = this.store.findById(other);
		String rotated = session.changeSessionId(); this.store.save(session); assertThat(rotated).isNotEqualTo(other); assertThat(publicId(rotated)).isEqualTo(id);
		var response = revoke(id); assertThat(response.statusCode()).isEqualTo(204); assertSecurityHeaders(response);
		assertThat(this.store.findById(rotated)).isNull(); assertThat(get("/api/me").statusCode()).isEqualTo(200);
		assertThat(response.headers().allValues("Set-Cookie")).noneMatch(value -> value.contains("Max-Age=0"));
		assertThat(revoke(id).statusCode()).isEqualTo(404); assertThat(revocationCount()).isEqualTo(1);
		var audit = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='browser_session_revoked'").query().singleRow();
		assertThat(audit).containsEntry("target_type", "browser_session").containsEntry("target_id", id).containsEntry("target_user_id", this.userId).containsEntry("actor", "user:" + this.userId);
		assertThat(audit.toString()).doesNotContain(other, rotated, this.sessionId);
	}

	@Test
	void revokingTheCallingBrowserClearsItsCookieAndCannotRecreateItsCommittedSession() throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); UUID id = publicId(this.sessionId);
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		var response = revoke(id); assertThat(response.statusCode()).as(response.body()).isEqualTo(204);
		assertThat(response.headers().allValues("Set-Cookie")).anyMatch(value -> value.startsWith("__Host-IAMSESSION=") && value.contains("Max-Age=0"));
		assertThat(get("/api/me").statusCode()).isEqualTo(401); assertThat(this.store.findById(this.sessionId)).isNull(); assertThat(this.store.findById(other)).isNotNull();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session_attributes WHERE session_primary_id=:id").param("id", id.toString()).query(Long.class).single()).isZero();
		assertThat(new IdentityAccessTokenVerifier(this.access, "https://iam.example").verify(issued.getAccessToken().getTokenValue())).isPresent();
		assertThat(revocationCount()).isEqualTo(1); assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='browser_session_ended'").query(Long.class).single()).isZero();
	}

	@Test
	void sourceBrowserRemovalBlocksUnredeemedCodesWhileAnIssuedOfflineGrantStillRefreshes() throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); String source = this.sessionId;
		String pending; String exchanged;
		try { this.sessionId=other; pending=code(Set.of("openid")); exchanged=code(Set.of("openid", "offline_access")); }
		finally { this.sessionId=source; }
		var issued = exchange(request(exchanged, authenticatedClient(exchanged))); assertThat(revoke(publicId(other)).statusCode()).isEqualTo(204);
		rejection(request(pending, authenticatedClient(pending)), "invalid_grant");
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		assertThat(provider.authenticate(new OAuth2RefreshTokenAuthenticationToken(issued.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), Map.of()))).isNotNull();
	}

	@Test
	void unknownForeignAndBearerCookieIdentifiersNeverResolveToAnOwnedManagementTarget() throws Exception {
		String foreign = browserSession(activeUser("bobby"), this.authenticatedAt);
		for (UUID id : List.of(publicId(foreign), UUID.randomUUID(), UUID.fromString(this.sessionId))) {
			var response = revoke(id); assertThat(response.statusCode()).isEqualTo(404); assertThat(response.body()).isEmpty();
		}
		assertThat(this.store.findById(foreign)).isNotNull(); assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isZero();
		var denied = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='browser_session_access_denied'").query().listOfRows();
		assertThat(denied).hasSize(3).allSatisfy(event -> assertThat(event).containsEntry("target_user_id", this.userId).containsEntry("target_id", null));
		assertThat(denied.toString()).doesNotContain(foreign, publicId(foreign).toString(), this.sessionId);
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "other-session" })
	void targetedRemovalRequiresCsrfFromTheCallingSession(String type) throws Exception {
		String target = browserSession(this.userId, this.authenticatedAt); String token = type.equals("missing") ? null : csrf(target);
		assertThat(send(path(publicId(target)), "POST", this.sessionId, token, null, Map.of()).statusCode()).isEqualTo(403);
		assertThat(this.store.findById(target)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "pageSize=0", "pageSize=101", "pageSize=1&pageSize=2", "pageSize=invalid", "cursor=", "cursor=bad", "userId=other" })
	void malformedQueriesAreRejectedWithoutInvalidatingTheCallingSession(String query) throws Exception {
		assertThat(get(ENDPOINT + "?" + query).statusCode()).isEqualTo(400); assertThat(get("/api/me").statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = { "owner", "precision", "before-epoch", "malformed-time" })
	void cursorOwnerAndTimestampRepresentationAreValidated(String change) throws Exception {
		String owner = change.equals("owner") ? UUID.randomUUID().toString() : this.userId.toString();
		String time = change.equals("precision") ? "2026-10-20T01:02:03.000001Z" : change.equals("before-epoch") ? "1969-01-01T00:00:00Z" : change.equals("malformed-time") ? "invalid" : "2026-10-20T01:02:03Z";
		String cursor = Base64.getUrlEncoder().withoutPadding().encodeToString(("1\n" + owner + "\n" + time + "\n" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
		assertThat(get(ENDPOINT + "?cursor=" + encode(cursor)).statusCode()).isEqualTo(400);
		assertThat(get("/api/me").statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = { "body", "query", "GET", "DELETE", "PATCH" })
	void malformedRemovalTransportCannotChangeItsTarget(String type) throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); String path = path(publicId(other));
		var response = send(path + (type.equals("query") ? "?target=other" : ""), Set.of("GET", "DELETE", "PATCH").contains(type) ? type : "POST",
				this.sessionId, csrf(this.sessionId), type.equals("body") ? "{}" : null, Map.of());
		assertThat(response.statusCode()).isEqualTo(Set.of("GET", "DELETE", "PATCH").contains(type) ? 403 : 400); assertThat(this.store.findById(other)).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "wrong-length", "object", "header" })
	void storedAuthenticationTimesAreCheckedAsPrimitiveEncodingsWithoutDeserializingObjects(String type) throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt);
		if (type.equals("header")) {
			byte[] corrupted = SerializationUtils.serialize(this.authenticatedAt); corrupted[0] ^= 1;
			this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes=:bytes WHERE session_primary_id=:id AND attribute_name='iam.authenticatedAt'")
					.param("bytes", corrupted).param("id", publicId(other).toString()).update();
		}
		else { attribute(other, "iam.authenticatedAt", type.equals("object") ? "private encoded object" : new byte[0]); }
		var response = get(ENDPOINT); assertThat(response.statusCode()).isEqualTo(503); assertThat(response.body()).doesNotContain("private encoded object", other);
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-suppressed", "audit-altered", "audit-deferred", "delete-suppressed", "delete-deferred", "save-suppressed" })
	void deletionAndAuditFailuresPreserveBothSessionsAndTheirAttributes(String failure) throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); UUID id = publicId(other); String token = csrf(this.sessionId);
		String table = failure.startsWith("audit") ? "iam_security_audit" : "iam_browser_session";
		boolean deferred = failure.endsWith("deferred"); String operation = failure.startsWith("audit") ? "INSERT" : failure.startsWith("save") ? "UPDATE" : "DELETE";
		String body = failure.equals("audit-altered") ? "IF NEW.action='browser_session_revoked' THEN NEW.source='altered'; END IF; RETURN NEW;"
				: failure.equals("audit-suppressed") ? "IF NEW.action='browser_session_revoked' THEN RETURN NULL; END IF; RETURN NEW;"
				: failure.endsWith("suppressed") ? operation.equals("DELETE") ? "RETURN NULL;" : "RETURN OLD;" : "RAISE EXCEPTION 'private browser removal fault';";
		fault(table, (deferred ? "AFTER " : "BEFORE ") + operation, body, deferred);
		var response = send(path(id), "POST", this.sessionId, token, null, Map.of());
		assertThat(response.statusCode()).as(response.body()).isEqualTo(503); assertThat(response.body()).doesNotContain(other, "private browser removal fault");
		assertThat(this.store.findById(other)).isNotNull(); assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session_attributes WHERE session_primary_id=:id").param("id", id.toString()).query(Long.class).single()).isEqualTo(3);
	}

	@Test
	void failedCurrentSessionDeletionDoesNotClearItsCookieOrPublishACommittedSuccess() throws Exception {
		String token = csrf(this.sessionId); UUID id = publicId(this.sessionId);
		fault("iam_security_audit", "AFTER INSERT", "IF NEW.action='browser_session_revoked' THEN RAISE EXCEPTION 'deferred current-session failure'; END IF; RETURN NEW;", true);
		var response = send(path(id), "POST", this.sessionId, token, null, Map.of());
		assertThat(response.statusCode()).isEqualTo(503); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void aSessionPersistenceCallbackFailureRollsBackBeforeAnyDeletion() {
		String other = browserSession(this.userId, this.authenticatedAt);
		assertThatIllegalStateException().isThrownBy(() -> this.management.revoke(browser(), publicId(other), () -> { throw new IllegalStateException("save failed"); }));
		assertThat(this.store.findById(other)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void expiryDuringSessionPersistenceCannotCommitTheDeletionOrItsSuccessAudit() {
		String other = browserSession(this.userId, this.authenticatedAt); long deadline = System.currentTimeMillis() + 800;
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", deadline).param("id", this.sessionId).update();
		assertThatIllegalStateException().isThrownBy(() -> this.management.revoke(browser(), publicId(other), () ->
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT :expiry <= extract(epoch FROM clock_timestamp()) * 1000").param("expiry", deadline).query(Boolean.class).single())));
		assertThat(this.store.findById(other)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void neitherAnonymousCallsNorApplicationBearerTokensCanListBrowserSessions() throws Exception {
		assertThat(send(ENDPOINT, "GET", null, null, null, Map.of()).statusCode()).isEqualTo(401);
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code)));
		assertThat(send(ENDPOINT, "GET", null, null, null, Map.of("Authorization", "Bearer " + issued.getAccessToken().getTokenValue())).statusCode()).isEqualTo(401);
	}

	@Test
	void staleCallingEvidenceCannotReadOrDeleteSessionsEvenThroughTheTrustedService() {
		String other = browserSession(this.userId, this.authenticatedAt); var context = browser(); mutate("credential");
		assertThat(this.management.list(context, 20, null, () -> fail("Stale session persisted")).outcome()).isEqualTo(IdentityAccountSessions.Outcome.INVALID_SESSION);
		assertThat(this.management.revoke(context, publicId(other), () -> fail("Stale session persisted")).outcome()).isEqualTo(IdentityAccountSessions.Outcome.INVALID_SESSION);
		assertThat(this.store.findById(other)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void swaggerDescribesOnlyGetAndPostWithPublicSessionMetadataAndHeaderCsrf() throws Exception {
		var document = success(get("/v3/api-docs")); var listing = document.path("paths").path(ENDPOINT);
		assertThat(listing.propertyNames()).containsExactly("get"); assertThat(listing.path("get").path("operationId").asText()).isEqualTo("listCurrentBrowserSessions");
		var removal = document.path("paths").path(ENDPOINT + "/{sessionId}/revoke"); assertThat(removal.propertyNames()).containsExactly("post");
		assertThat(removal.path("post").has("requestBody")).isFalse(); assertThat(removal.path("post").path("responses").has("404")).isTrue();
		assertThat(document.path("components").path("schemas").path("IdentityBrowserSessionResponse").path("properties").propertyNames())
				.containsExactlyInAnyOrder("id", "createdAt", "authenticatedAt", "lastAccessedAt", "idleExpiresAt", "absoluteExpiresAt", "current");
	}

	private IdentityBrowserContext browser() { return new IdentityBrowserContext(this.userId, this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()); }
	private UUID publicId(String cookie) { return this.jdbc.sql("SELECT primary_id FROM iam_browser_session WHERE session_id=:id").param("id", cookie).query((row, index) -> UUID.fromString(row.getString(1))).single(); }
	private void attribute(String session, String name, Object value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes=:bytes WHERE session_primary_id=(SELECT primary_id FROM iam_browser_session WHERE session_id=:id) AND attribute_name=:name")
				.param("bytes", SerializationUtils.serialize(value)).param("id", session).param("name", name).update();
	}
	private String csrf(String session) throws Exception { return success(send("/api/csrf", "GET", session, null, null, Map.of())).path("token").asText(); }
	private static String path(UUID id) { return ENDPOINT + "/" + id + "/revoke"; }
	private HttpResponse<String> revoke(UUID id) throws Exception { return send(path(id), "POST", this.sessionId, csrf(this.sessionId), null, Map.of()); }
	private HttpResponse<String> get(String path) throws Exception { return send(path, "GET", this.sessionId, null, null, Map.of()); }
	private HttpResponse<String> send(String path, String method, String session, String token, String body, Map<String, String> headers) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (session != null) { builder.header("Cookie", "__Host-IAMSESSION=" + session); } if (token != null) { builder.header("X-CSRF-TOKEN", token); } headers.forEach(builder::header);
		try (var client = client()) { return client.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private static JsonNode success(HttpResponse<String> response) { assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response); return JSON.readTree(response.body()); }
	private long revocationCount() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='browser_session_revoked'").query(Long.class).single(); }
}
