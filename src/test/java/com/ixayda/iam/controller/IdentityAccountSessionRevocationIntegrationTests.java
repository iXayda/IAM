package com.ixayda.iam.controller;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.security.IdentityAccessTokenVerifier;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;
import com.ixayda.iam.service.IdentityAccountSessions;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityAuthentications;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityBrowserSessions;

import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityAccountSessionRevocationIntegrationTests extends IdentityProtocolTestSupport {

	private static final String ENDPOINT = "/api/me/sessions/revoke-all";
	private static final JsonMapper JSON = new JsonMapper();
	@LocalServerPort private int port;
	@Autowired private IdentityAccountSessions management;
	@Autowired private IdentityAccessTokens access;
	@Autowired private IdentityAuthentications authentications;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true); registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@AfterEach
	void removeSessionAndEpochFaults() {
		for (String table : List.of("iam_browser_session", "iam_password")) { this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON " + table).update(); }
	}

	@Test
	void allOfflineCoversMoreThanOnePageAndPreservesTheAccountPasswordAndOtherUsers() throws Exception {
		UUID foreign = activeUser("bobby"); String foreignBrowser = browserSession(foreign, this.authenticatedAt);
		this.assignments.change(foreign, this.roleId, 0, true, AUDIT);
		UUID originalUser = this.userId; String originalSession = this.sessionId; String foreignCode;
		try { this.userId=foreign; this.sessionId=foreignBrowser; foreignCode=code(Set.of("openid")); }
		finally { this.userId=originalUser; this.sessionId=originalSession; }
		String hash = hash(); var identity = this.users.findById(this.userId);
		var codes = new ArrayList<String>();
		for (int index = 0; index < 101; index++) { codes.add(code(Set.of("openid", "offline_access"))); browserSession(this.userId, this.authenticatedAt); }
		var tokens = exchange(request(codes.getFirst(), authenticatedClient(codes.getFirst())));
		var response = revoke(); assertThat(response.statusCode()).as(response.body()).isEqualTo(204); assertSecurityHeaders(response);
		assertThat(response.headers().allValues("Set-Cookie")).anyMatch(value -> value.startsWith("__Host-IAMSESSION=") && value.contains("Max-Age=0"));
		assertThat(browserCount()).isZero(); assertThat(version()).isEqualTo(2); assertThat(hash()).isEqualTo(hash); assertThat(this.users.findById(this.userId)).isEqualTo(identity);
		assertThat(this.store.findById(foreignBrowser)).isNotNull(); assertThat(IdentityAuthorizations.isRevoked(stored(foreignCode).authorization())).isFalse();
		for (String code : codes) { assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue(); }
		assertThat(this.refresh.findByAuthorization(stored(codes.getFirst()).authorization()).orElseThrow().status()).isEqualTo(IdentityRefreshFamily.Status.REVOKED);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='authorization_revoked' AND target_user_id=:id").param("id", this.userId).query(Long.class).single()).isEqualTo(101);
		assertThat(new IdentityAccessTokenVerifier(this.access, "https://iam.example").verify(tokens.getAccessToken().getTokenValue())).isEmpty();
		rejection(request(codes.getLast(), authenticatedClient(codes.getLast())), "invalid_grant");
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		assertThatThrownBy(() -> provider.authenticate(new OAuth2RefreshTokenAuthenticationToken(tokens.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), Map.of())))
				.isInstanceOf(OAuth2AuthenticationException.class);
		assertThat(revocationCount()).isEqualTo(1); assertThat(send(ENDPOINT, "POST", this.sessionId, null, null, Map.of()).statusCode()).isEqualTo(403); assertThat(revocationCount()).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='browser_session_ended'").query(Long.class).single()).isZero();
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='all_sessions_revoked'").query().singleRow();
		assertThat(event).containsEntry("target_user_id", this.userId).containsEntry("actor", "user:" + this.userId).containsEntry("source", "browser:account-sessions");
		assertThat(event.toString()).doesNotContain(this.sessionId, this.secret, hash, tokens.getAccessToken().getTokenValue());
		assertThat(this.authentications.authenticate("alice", PASSWORD, passwordContext()).orElseThrow().credentialVersion()).isEqualTo(2);
	}

	@Test
	@SuppressWarnings("unchecked")
	void aPasswordDecisionMadeBeforeAllOfflineCannotCreateANewSessionAfterwards() throws Exception {
		var evidence = this.authentications.authenticate("alice", PASSWORD, passwordContext()).orElseThrow();
		var decorated = (SessionRepository<Session>) this.context.getBean("sessionRepository", SessionRepository.class);
		var pending = decorated.createSession();
		pending.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT, new SecurityContextImpl(UsernamePasswordAuthenticationToken.authenticated(this.userId, null, List.of())));
		pending.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, evidence.credentialVersion()); pending.setAttribute(IdentityBrowserSessions.LOGIN_PENDING, true);
		assertThat(revoke().statusCode()).isEqualTo(204);
		assertThatIllegalStateException().isThrownBy(() -> decorated.save(pending));
		assertThat(this.store.findById(pending.getId())).isNull(); assertThat(browserCount()).isZero();
		var current = this.authentications.authenticate("alice", PASSWORD, passwordContext()).orElseThrow();
		var fresh = decorated.createSession(); fresh.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT,
				new SecurityContextImpl(UsernamePasswordAuthenticationToken.authenticated(this.userId, null, List.of())));
		fresh.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, current.credentialVersion()); fresh.setAttribute(IdentityBrowserSessions.LOGIN_PENDING, true);
		decorated.save(fresh); assertThat(this.store.findById(fresh.getId())).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-suppressed", "audit-altered", "audit-deferred", "delete-suppressed", "epoch-suppressed", "epoch-altered", "epoch-deferred", "native-suppressed", "save-suppressed" })
	void anyMandatoryFailureRollsBackEpochBrowserGrantFamilyAndAudits(String failure) throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code)));
		var grant = stored(code); var family = this.refresh.findByAuthorization(grant.authorization()); String token = csrf(this.sessionId); String hash = hash();
		String table = failure.startsWith("audit") ? "iam_security_audit" : failure.startsWith("epoch") ? "iam_password" : failure.startsWith("native") ? "iam_authorization_record" : "iam_browser_session";
		boolean deferred = failure.endsWith("deferred"); String operation = failure.startsWith("audit") ? "INSERT" : failure.startsWith("delete") ? "DELETE" : "UPDATE";
		String body = failure.equals("audit-suppressed") ? "IF NEW.action='all_sessions_revoked' THEN RETURN NULL; END IF; RETURN NEW;"
				: failure.equals("audit-altered") ? "IF NEW.action='all_sessions_revoked' THEN NEW.source='altered'; END IF; RETURN NEW;"
				: failure.equals("epoch-altered") ? "NEW.credential_version=NEW.credential_version+1; RETURN NEW;"
				: failure.endsWith("suppressed") ? operation.equals("DELETE") ? "RETURN NULL;" : "RETURN OLD;" : "RAISE EXCEPTION 'private all-offline fault';";
		fault(table, (deferred ? "AFTER " : "BEFORE ") + operation, body, deferred);
		var response = send(ENDPOINT, "POST", this.sessionId, token, null, Map.of());
		assertThat(response.statusCode()).as(response.body()).isEqualTo(503); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(response.body()).doesNotContain(this.sessionId, this.secret, "private all-offline fault");
		assertThat(version()).isEqualTo(1); assertThat(hash()).isEqualTo(hash); assertThat(this.store.findById(other)).isNotNull(); assertThat(this.store.findById(this.sessionId)).isNotNull();
		assertThat(stored(code)).isEqualTo(grant); assertThat(this.refresh.findByAuthorization(grant.authorization())).isEqualTo(family); assertThat(revocationCount()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action IN ('browser_sessions_revoked','authorization_revoked')").query(Long.class).single()).isZero();
	}

	@Test
	void sourceExpiryDuringPersistenceRollsBackAllOfflineWithoutCommittingANewEpoch() {
		String code = code(Set.of("openid")); long deadline = System.currentTimeMillis() + 800;
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", deadline).param("id", this.sessionId).update();
		assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(browser(), () ->
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT :expiry <= extract(epoch FROM clock_timestamp()) * 1000").param("expiry", deadline).query(Boolean.class).single())));
		assertThat(version()).isEqualTo(1); assertThat(browserCount()).isEqualTo(1); assertThat(revocationCount()).isZero(); assertUnconsumed(code);
	}

	@Test
	void aFailedSessionCallbackOrStaleCallerCannotStartAllOffline() {
		assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(browser(), () -> { throw new IllegalStateException("session failed"); }));
		assertThat(version()).isEqualTo(1); assertThat(revocationCount()).isZero();
		var context = browser(); mutate("credential");
		assertThat(this.management.revokeAll(context, () -> fail("Stale evidence persisted")).outcome()).isEqualTo(IdentityAccountSessions.Outcome.INVALID_SESSION);
		assertThat(version()).isEqualTo(2); assertThat(browserCount()).isEqualTo(1); assertThat(revocationCount()).isZero();
	}

	@Test
	void anOwnerLockWaitRechecksTheCredentialEpochBeforeDeletingAnySession() throws Exception {
		var browser = browser(); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
				mutate("credential"); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var removal = executor.submit(() -> this.management.revokeAll(browser, () -> fail("Stale session saved")));
			try { await().atMost(Duration.ofSeconds(5)).until(() -> waiting("iam_user")); } finally { release.countDown(); }
			writer.get(10, TimeUnit.SECONDS); assertThat(removal.get(10, TimeUnit.SECONDS).outcome()).isEqualTo(IdentityAccountSessions.Outcome.INVALID_SESSION);
		}
		assertThat(version()).isEqualTo(2); assertThat(browserCount()).isEqualTo(1); assertThat(revocationCount()).isZero();
	}

	@Test
	void sourceExpiryWhileWaitingForANativeLockRollsBackTheEpochAndAllBrowserDeletions() throws Exception {
		String code = code(Set.of("openid")); var before = stored(code); var browser = browser();
		long deadline = System.currentTimeMillis() + 1800;
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", deadline).param("id", this.sessionId).update();
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.authorizations.lockForUse(UUID.fromString(before.authorization().getId())); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var removal = executor.submit(() -> assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(browser, () -> { })));
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> waiting("pg_advisory_xact_lock"));
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT :expiry <= extract(epoch FROM clock_timestamp()) * 1000").param("expiry", deadline).query(Boolean.class).single());
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS); removal.get(10, TimeUnit.SECONDS);
		}
		assertThat(stored(code)).isEqualTo(before); assertThat(version()).isEqualTo(1); assertThat(browserCount()).isEqualTo(1); assertThat(revocationCount()).isZero();
	}

	@Test
	void anAmbientTransactionCannotHideTheRevocationCommitBoundary() {
		new TransactionTemplate(this.transactions).executeWithoutResult(tx ->
				assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(browser(), () -> fail("Unexpected session save"))));
		assertThat(version()).isEqualTo(1); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-csrf", "other-csrf", "body", "query", "GET", "DELETE", "PATCH", "anonymous", "bearer" })
	void invalidTransportAndAuthenticationCannotRevokeAnything(String type) throws Exception {
		String other = browserSession(this.userId, this.authenticatedAt); String csrf = type.equals("missing-csrf") ? null : csrf(type.equals("other-csrf") ? other : this.sessionId);
		String cookie = Set.of("anonymous", "bearer").contains(type) ? null : this.sessionId;
		Map<String, String> headers = type.equals("bearer") ? Map.of("Authorization", "Bearer invalid") : Map.of();
		var response = send(ENDPOINT + (type.equals("query") ? "?userId=other" : ""), Set.of("GET", "DELETE", "PATCH").contains(type) ? type : "POST", cookie, csrf, type.equals("body") ? "{}" : null, headers);
		assertThat(response.statusCode()).isEqualTo(Set.of("body", "query").contains(type) ? 400 : 403);
		assertThat(version()).isEqualTo(1); assertThat(browserCount()).isEqualTo(2); assertThat(revocationCount()).isZero();
	}

	@Test
	void swaggerDescribesTheCombinedOperationAndItsRevocationLimits() throws Exception {
		var response = send("/v3/api-docs", "GET", this.sessionId, null, null, Map.of()); assertThat(response.statusCode()).isEqualTo(200);
		var path = JSON.readTree(response.body()).path("paths").path(ENDPOINT); assertThat(path.propertyNames()).containsExactly("post");
		var operation = path.path("post"); assertThat(operation.path("operationId").asText()).isEqualTo("revokeAllCurrentSessions");
		assertThat(operation.has("requestBody")).isFalse(); assertThat(operation.path("responses").has("204")).isTrue();
		assertThat(operation.path("description").asText()).contains("分页", "刷新", "离线", "本地会话");
	}

	private IdentityBrowserContext browser() { return new IdentityBrowserContext(this.userId, this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()); }
	private PasswordAuthenticationContext passwordContext() { return new PasswordAuthenticationContext("internal:all-offline-test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private boolean waiting(String query) { return this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE :query").param("query", "%" + query + "%").query(Long.class).single() > 0; }
	private long version() { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id=:id").param("id", this.userId).query(Long.class).single(); }
	private String hash() { return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id=:id").param("id", this.userId).query(String.class).single(); }
	private long browserCount() { return this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name=:id").param("id", this.userId.toString()).query(Long.class).single(); }
	private long revocationCount() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='all_sessions_revoked'").query(Long.class).single(); }
	private String csrf(String cookie) throws Exception { var response = send("/api/csrf", "GET", cookie, null, null, Map.of()); assertThat(response.statusCode()).isEqualTo(200); return JSON.readTree(response.body()).path("token").asText(); }
	private HttpResponse<String> revoke() throws Exception { return send(ENDPOINT, "POST", this.sessionId, csrf(this.sessionId), null, Map.of()); }
	private HttpResponse<String> send(String path, String method, String cookie, String csrf, String body, Map<String, String> headers) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (cookie != null) { request.header("Cookie", "__Host-IAMSESSION=" + cookie); } if (csrf != null) { request.header("X-CSRF-TOKEN", csrf); } headers.forEach(request::header);
		try (var client = client()) { return client.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
}
