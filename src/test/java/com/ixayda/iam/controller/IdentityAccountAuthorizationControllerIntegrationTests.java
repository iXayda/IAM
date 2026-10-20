package com.ixayda.iam.controller;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.security.IdentityAccessTokenVerifier;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;
import com.ixayda.iam.service.IdentityAccountAuthorizations;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityAuthorizations;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityAccountAuthorizationControllerIntegrationTests extends IdentityProtocolTestSupport {

	private static final String ENDPOINT = "/api/me/authorizations";
	private static final JsonMapper JSON = new JsonMapper();
	@LocalServerPort private int port;
	@Autowired private IdentityAccountAuthorizations management;
	@Autowired private IdentityAccessTokens access;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true); registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@Test
	void ownerPagesOnlyPublicGrantMetadataAndRetrievesNoCredentialsOrBrowserIdentifiers() throws Exception {
		String first = code(Set.of("openid", "offline_access")); var issued = exchange(request(first, authenticatedClient(first)));
		String second = code(Set.of("openid", "profile")); String third = code(Set.of("openid")); String foreign = foreignCode();
		var page = success(get(ENDPOINT + "?pageSize=1"));
		assertThat(page.propertyNames()).containsExactlyInAnyOrder("items", "nextCursor"); assertThat(page.path("items").size()).isEqualTo(1);
		var item = page.path("items").get(0);
		assertThat(item.propertyNames()).containsExactlyInAnyOrder("id", "clientId", "clientName", "resourceId", "resourceName", "audience", "issuedAt", "expiresAt", "scopes", "status");
		assertThat(item.path("id").asText()).isEqualTo(id(first).toString()); assertThat(item.path("status").asText()).isEqualTo("ACTIVE");
		assertThat(item.path("clientName").asText()).isEqualTo("Orders"); assertThat(item.path("resourceName").asText()).isEqualTo("Orders");
		assertThat(item.path("resourceId").asText()).isEqualTo(this.resourceId.toString()); assertThat(item.path("audience").asText()).isEqualTo("urn:example:orders");
		String cursor = page.path("nextCursor").asText(); assertThat(cursor).isNotBlank();
		var next = success(get(ENDPOINT + "?pageSize=1&cursor=" + encode(cursor)));
		assertThat(next.path("items").get(0).path("id").asText()).isEqualTo(id(second).toString());
		var last = success(get(ENDPOINT + "?pageSize=1&cursor=" + encode(next.path("nextCursor").asText())));
		assertThat(last.path("items").get(0).path("id").asText()).isEqualTo(id(third).toString()); assertThat(last.path("nextCursor").isNull()).isTrue();
		String all = page.toString() + next + last;
		assertThat(all).doesNotContain(first, second, third, foreign, id(foreign).toString(), this.sessionId, this.secret, PASSWORD,
				issued.getAccessToken().getTokenValue(), issued.getRefreshToken().getTokenValue(), "ROLE_IAM_ADMIN");
		assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "code", "access", "refresh" })
	void revokingOneGrantPreservesBrowserAuthenticationAndOtherGrantsAndCannotBeUndone(String kind) throws Exception {
		String code = code(kind.equals("refresh") ? Set.of("openid", "offline_access") : Set.of("openid"));
		var issued = kind.equals("code") ? null : exchange(request(code, authenticatedClient(code)));
		String other = code(Set.of("openid"));
		var before = stored(code); var response = revoke(id(code));
		assertThat(response.statusCode()).isEqualTo(204); assertSecurityHeaders(response); assertThat(response.body()).isEmpty();
		var saved = stored(code); assertThat(IdentityAuthorizations.isRevoked(saved.authorization())).isTrue(); assertThat(saved.version()).isEqualTo(before.version() + 1);
		assertThat(IdentityAuthorizations.isRevoked(stored(other).authorization())).isFalse(); assertThat(get("/api/me").statusCode()).isEqualTo(200);
		assertThat(revoke(id(code)).statusCode()).isEqualTo(204); assertThat(stored(code)).isEqualTo(saved); assertThat(revocationCount()).isEqualTo(1);
		var audit = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='authorization_revoked'").query().singleRow();
		assertThat(audit).containsEntry("actor", "user:" + this.userId).containsEntry("target_user_id", this.userId).containsEntry("target_id", id(code))
				.containsEntry("source", "browser:account-authorizations");
		assertThat(summary(code).path("status").asText()).isEqualTo("REVOKED");
		if (issued != null) { assertThat(new IdentityAccessTokenVerifier(this.access, "https://iam.example").verify(issued.getAccessToken().getTokenValue())).isEmpty(); }
		else { rejection(request(code, authenticatedClient(code)), "invalid_grant"); }
	}

	@Test
	void anotherOwnersGrantAndAnUnknownGrantHaveTheSameResponseAndSafeDenialAttribution() throws Exception {
		String foreign = foreignCode(); var before = stored(foreign);
		for (UUID target : List.of(id(foreign), UUID.randomUUID())) {
			var response = revoke(target); assertThat(response.statusCode()).isEqualTo(404); assertThat(response.body()).isEmpty();
		}
		assertThat(stored(foreign)).isEqualTo(before); assertThat(revocationCount()).isZero();
		var denials = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='authorization_access_denied'").query().listOfRows();
		assertThat(denials).hasSize(2).allSatisfy(event -> assertThat(event).containsEntry("actor", "user:" + this.userId).containsEntry("target_user_id", this.userId).containsEntry("target_id", null));
		assertThat(denials.toString()).doesNotContain(id(foreign).toString(), foreign);
	}

	@Test
	void clientTransferKeepsTheOriginalResourceInTheOwnersGrantHistory() throws Exception {
		String code = code(Set.of("openid")); exchange(request(code, authenticatedClient(code))); mutate("client-transferred");
		var item = summary(code); assertThat(item.path("resourceId").asText()).isEqualTo(this.resourceId.toString());
		assertThat(item.path("audience").asText()).isEqualTo("urn:example:orders"); assertThat(item.path("status").asText()).isEqualTo("REVOKED");
	}

	@Test
	void nativeReplayQuarantineRemainsDistinctFromAnOrdinaryRevocationInTheListing() throws Exception {
		String code = code(Set.of("openid", "offline_access")); var issued = exchange(request(code, authenticatedClient(code)));
		var snapshot = stored(code);
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> this.refresh.quarantine(snapshot));
		assertThat(summary(code).path("status").asText()).isEqualTo("QUARANTINED");
		assertThat(revoke(id(code)).statusCode()).isEqualTo(204); assertThat(summary(code).path("status").asText()).isEqualTo("REVOKED");
		assertThat(summary(code).toString()).doesNotContain(issued.getRefreshToken().getTokenValue());
	}

	@Test
	void listingUsesTheActualNarrowedScopesAfterRefreshRatherThanTheOriginalAuthorization() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access")); var issued = exchange(request(code, authenticatedClient(code)));
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		provider.authenticate(new OAuth2RefreshTokenAuthenticationToken(issued.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of("profile"), Map.of()));
		var item = summary(code); assertThat(item.path("scopes").size()).isEqualTo(1); assertThat(item.path("scopes").get(0).asText()).isEqualTo("profile");
		assertThat(item.path("status").asText()).isEqualTo("ACTIVE"); assertThat(stored(code).authorization().getAuthorizedScopes()).contains("openid", "offline_access");
		assertThat(Instant.parse(item.path("expiresAt").asText())).isEqualTo(stored(code).authorization().getAccessToken().getToken().getExpiresAt().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
	}

	@ParameterizedTest
	@ValueSource(strings = { "wrong-time", "wrong-version", "foreign-session", "deleted", "expired" })
	void aTrustedAdapterStillCannotSubstituteStaleOrForeignBrowserEvidence(String type) {
		String code = code(Set.of("openid")); var before = stored(code); String session = this.sessionId; long time = this.authenticatedAt; long version = 1;
		switch (type) {
			case "wrong-time" -> time--; case "wrong-version" -> version++;
			case "foreign-session" -> session=browserSession(activeUser("bobby"), time);
			case "deleted" -> this.store.deleteById(session);
			default -> this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", session).update();
		}
		var evidence = new IdentityBrowserContext(this.userId, session, time, version, UUID.randomUUID());
		assertThat(this.management.revoke(evidence, id(code), () -> fail("Invalid session was persisted")).outcome()).isEqualTo(IdentityAccountAuthorizations.Outcome.INVALID_SESSION);
		assertThat(this.management.list(evidence, 20, null, () -> fail("Invalid session was persisted")).outcome()).isEqualTo(IdentityAccountAuthorizations.Outcome.INVALID_SESSION);
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "other-session" })
	void revocationRequiresCsrfFromTheExactCurrentSession(String type) throws Exception {
		String code = code(Set.of("openid")); var original = stored(code);
		String csrf = type.equals("missing") ? null : csrf(browserSession(this.userId, this.authenticatedAt));
		assertThat(send(path(id(code)), "POST", this.sessionId, csrf, null, Map.of()).statusCode()).isEqualTo(403);
		assertThat(stored(code)).isEqualTo(original); assertThat(revocationCount()).isZero();
	}

	@Test
	void applicationBearerTokensCannotListOrRevokeBrowserOwnedGrants() throws Exception {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code))); var before = stored(code);
		var response = send(ENDPOINT, "GET", null, null, null, Map.of("Authorization", "Bearer " + issued.getAccessToken().getTokenValue()));
		assertThat(response.statusCode()).isEqualTo(401);
		assertThat(send(path(id(code)), "POST", null, null, null, Map.of("Authorization", "Bearer " + issued.getAccessToken().getTokenValue())).statusCode()).isEqualTo(403);
		assertThat(stored(code)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "pageSize=0", "pageSize=101", "pageSize=1.5", "pageSize=bad", "pageSize=1&pageSize=2", "cursor=", "cursor=invalid", "userId=foreign", "status=ACTIVE" })
	void invalidListQueriesNeverTurnIntoSuccessfulOrDependencyErrorResponses(String query) throws Exception {
		var response = get(ENDPOINT + "?" + query); assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
		assertThat(get("/api/me").statusCode()).isEqualTo(200);
	}

	@Test
	void paginationCannotReuseAnotherOwnersCursorOrInjectPageSizeFromAHeader() throws Exception {
		code(Set.of("openid")); code(Set.of("openid"));
		var page = success(send(ENDPOINT, "GET", this.sessionId, null, null, Map.of("pageSize", "1")));
		assertThat(page.path("items").size()).isEqualTo(2); assertThat(page.path("nextCursor").isNull()).isTrue();
		String text = "1\n" + UUID.randomUUID() + "\n" + Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS) + "\n" + UUID.randomUUID();
		String cursor = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
		assertThat(get(ENDPOINT + "?cursor=" + encode(cursor)).statusCode()).isEqualTo(400);
	}

	@ParameterizedTest
	@ValueSource(strings = { "invalid", "2026-10-20T25:00:00Z", "+1000000001-01-01T00:00:00Z" })
	void malformedCursorTimesReturnBadRequestWithoutInvalidatingTheSession(String time) throws Exception {
		String text = "1\n" + this.userId + "\n" + time + "\n" + UUID.randomUUID();
		String cursor = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
		assertThat(get(ENDPOINT + "?cursor=" + encode(cursor)).statusCode()).isEqualTo(400);
		assertThat(get("/api/me").statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = { "list-body", "revoke-body", "revoke-query", "malformed-id", "GET", "DELETE", "PATCH" })
	void alternateInputsAndMethodsCannotChangeAGrant(String type) throws Exception {
		String code = code(Set.of("openid")); var before = stored(code); String target = path(id(code)); String method = "POST"; String body = null;
		switch (type) {
			case "list-body" -> { target=ENDPOINT; method="GET"; body="private-body"; }
			case "revoke-body" -> body="{}"; case "revoke-query" -> target+="?userId=private-user";
			case "malformed-id" -> target=ENDPOINT + "/bad/revoke"; default -> method=type;
		}
		var response = send(target, method, this.sessionId, csrf(this.sessionId), body, Map.of());
		assertThat(response.statusCode()).isEqualTo(Set.of("GET", "DELETE", "PATCH").contains(type) ? 403 : 400); assertThat(stored(code)).isEqualTo(before);
	}

	@Test
	void evenAnEmptyChunkedBodyIsNotAcceptedAsAnAlternateRevocationTransport() throws Exception {
		String code = code(Set.of("openid")); var before = stored(code);
		var request = HttpRequest.newBuilder(uri(path(id(code)))).timeout(Duration.ofSeconds(20))
				.header("Cookie", "__Host-IAMSESSION=" + this.sessionId).header("X-CSRF-TOKEN", csrf(this.sessionId))
				.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(new byte[0]))).build();
		try (var client = client()) { assertThat(client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(400); }
		assertThat(stored(code)).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-suppressed", "audit-altered", "audit-deferred", "native-suppressed", "native-deferred" })
	void persistenceAndMandatoryAuditFailuresRollBackGrantAndFamilyRevocation(String failure) throws Exception {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code))); var original = stored(code);
		String csrf = csrf(this.sessionId); var family = this.refresh.findByAuthorization(original.authorization());
		String table = failure.startsWith("audit") ? "iam_security_audit" : "oauth2_authorization";
		boolean deferred = failure.endsWith("deferred"); String timing = table.equals("iam_security_audit") ? "INSERT" : "UPDATE";
		String body = failure.equals("audit-altered") ? "IF NEW.action='authorization_revoked' THEN NEW.source='altered'; END IF; RETURN NEW;"
				: failure.endsWith("suppressed") ? table.equals("iam_security_audit") ? "IF NEW.action='authorization_revoked' THEN RETURN NULL; END IF; RETURN NEW;" : "RETURN OLD;"
				: "RAISE EXCEPTION 'private account authorization fault';";
		fault(table, (deferred ? "AFTER " : "BEFORE ") + timing, body, deferred);
		var response = send(path(id(code)), "POST", this.sessionId, csrf, null, Map.of());
		assertThat(response.statusCode()).as(response.body()).isEqualTo(503); assertThat(response.body()).doesNotContain("private account authorization fault", code, this.secret);
		assertThat(stored(code)).isEqualTo(original); assertThat(this.refresh.findByAuthorization(stored(code).authorization())).isEqualTo(family); assertThat(revocationCount()).isZero();
	}

	@Test
	void aFailureToPersistTheCallingSessionRollsBackRevocationAndItsSuccessAudit() {
		String code = code(Set.of("openid")); var before = stored(code);
		assertThatIllegalStateException().isThrownBy(() -> this.management.revoke(browser(), id(code), () -> { throw new IllegalStateException("session persistence failed"); }));
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationCount()).isZero();
	}

	@Test
	void missingOwnershipAuditCannotBeReplacedByAnUnauditedNotFoundResponse() throws Exception {
		String csrf = csrf(this.sessionId); fault("iam_security_audit", "BEFORE INSERT", "RETURN NULL;", false);
		assertThat(send(path(UUID.randomUUID()), "POST", this.sessionId, csrf, null, Map.of()).statusCode()).isEqualTo(503);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='authorization_access_denied'").query(Long.class).single()).isZero();
	}

	@Test
	void waitingForTheOwnerLockCannotReuseAnAuthenticationSnapshotAfterItsCredentialChanges() throws Exception {
		String code = code(Set.of("openid")); var before = stored(code); var browser = browser(); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var change = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
				mutate("credential"); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var revoked = executor.submit(() -> this.management.revoke(browser, id(code), () -> fail("Stale session was saved")));
			try { await().atMost(Duration.ofSeconds(5)).until(() -> waiting("iam_user")); } finally { release.countDown(); }
			change.get(10, TimeUnit.SECONDS); assertThat(revoked.get(10, TimeUnit.SECONDS).outcome()).isEqualTo(IdentityAccountAuthorizations.Outcome.INVALID_SESSION);
		}
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationCount()).isZero();
	}

	@Test
	void aSessionThatExpiresWhileWaitingForTheNativeGrantCannotCommitARevocation() throws Exception {
		String code = code(Set.of("openid")); var before = stored(code); var browser = browser();
		long deadline = System.currentTimeMillis() + 1800;
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", deadline).param("id", this.sessionId).update();
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.authorizations.lockForUse(id(code)); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var revoked = executor.submit(() -> assertThatIllegalStateException().isThrownBy(() -> this.management.revoke(browser, id(code), () -> { })));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> waiting("pg_advisory_xact_lock"));
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() >= deadline);
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS); revoked.get(10, TimeUnit.SECONDS);
		}
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationCount()).isZero();
	}

	@Test
	void swaggerDescribesOwnerOnlyPaginationAndBodylessCsrfProtectedRevocation() throws Exception {
		var document = success(get("/v3/api-docs")); var listing = document.path("paths").path(ENDPOINT).path("get");
		assertThat(listing.path("operationId").asText()).isEqualTo("listCurrentAuthorizations"); assertThat(listing.has("requestBody")).isFalse();
		var parameters = listing.path("parameters"); assertThat(parameters.size()).isEqualTo(2);
		assertThat(parameters.get(0).path("name").asText()).isEqualTo("pageSize"); assertThat(parameters.get(0).path("schema").path("maximum").asInt()).isEqualTo(100);
		var path = document.path("paths").path(ENDPOINT + "/{authorizationId}/revoke"); assertThat(path.propertyNames()).containsExactly("post");
		var revoke = path.path("post"); assertThat(revoke.path("operationId").asText()).isEqualTo("revokeCurrentAuthorization");
		assertThat(revoke.has("requestBody")).isFalse(); assertThat(revoke.path("responses").has("404")).isTrue();
		assertThat(document.path("components").path("schemas").path("IdentityAuthorizationResponse").path("properties").propertyNames())
				.containsExactlyInAnyOrder("id", "clientId", "clientName", "resourceId", "resourceName", "audience", "issuedAt", "expiresAt", "scopes", "status");
	}

	private IdentityBrowserContext browser() { return new IdentityBrowserContext(this.userId, this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()); }
	private UUID id(String code) { return UUID.fromString(stored(code).authorization().getId()); }
	private String foreignCode() {
		var owner = this.userId; var session = this.sessionId;
		try { this.userId = activeUser("bobby"); this.sessionId = browserSession(this.userId, this.authenticatedAt); return code(Set.of("openid")); }
		finally { this.userId = owner; this.sessionId = session; }
	}
	private String csrf(String session) throws Exception { return success(send("/api/csrf", "GET", session, null, null, Map.of())).path("token").asText(); }
	private static String path(UUID id) { return ENDPOINT + "/" + id + "/revoke"; }
	private HttpResponse<String> revoke(UUID id) throws Exception { return send(path(id), "POST", this.sessionId, csrf(this.sessionId), null, Map.of()); }
	private HttpResponse<String> get(String path) throws Exception { return send(path, "GET", this.sessionId, null, null, Map.of()); }
	private HttpResponse<String> send(String path, String method, String session, String csrf, String body, Map<String, String> headers) throws Exception {
		var builder = HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(20));
		if (session != null) { builder.header("Cookie", "__Host-IAMSESSION=" + session); } if (csrf != null) { builder.header("X-CSRF-TOKEN", csrf); } headers.forEach(builder::header);
		try (var client = client()) { return client.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private URI uri(String path) { return URI.create("https://localhost:" + this.port + path); }
	private static JsonNode success(HttpResponse<String> response) { assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response); return JSON.readTree(response.body()); }
	private JsonNode summary(String code) throws Exception {
		String id = id(code).toString(); var page = success(get(ENDPOINT));
		for (var item : page.path("items")) { if (id.equals(item.path("id").asText())) { return item; } }
		throw new AssertionError("Owned grant was not listed");
	}
	private long revocationCount() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='authorization_revoked'").query(Long.class).single(); }
	private boolean waiting(String table) { return this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE :query").param("query", "%" + table + "%").query(Long.class).single() > 0; }
}
