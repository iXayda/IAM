package com.ixayda.iam.controller;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
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
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityAccessTokenVerifier;
import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityUserSessionManagement;
import com.ixayda.iam.service.IdentityUserStates;

import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityUserSessionControllerIntegrationTests extends IdentityProtocolTestSupport {

	private static final JsonMapper JSON = new JsonMapper();
	private static final Path TOTP_KEY = keyFile();
	@LocalServerPort private int port;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityAccessTokens access;
	@Autowired private IdentityUserSessionManagement management;

	@DynamicPropertySource
	static void tlsAndTotp(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true); registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password"); registry.add("iam.totp.key-file", TOTP_KEY::toString);
		registry.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@AfterEach
	void removeSessionAndEpochFaults() {
		for (String table : List.of("iam_browser_session", "iam_password")) { this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON " + table).update(); }
	}

	@Test
	void aFreshAdministratorTotpRevokesOnlyTheTargetAndPreservesTheActingSession() throws Exception {
		var administrator = administrator(); String other = browserSession(this.userId, this.authenticatedAt);
		String code = code(Set.of("openid", "offline_access")); var tokens = exchange(request(code, authenticatedClient(code))); String hash = hash(this.userId);
		String otp = freshCode(administrator.factor());
		var response = force(this.userId, administrator.session(), otp); assertThat(response.statusCode()).as(response.body()).isEqualTo(204); assertSecurityHeaders(response);
		assertThat(this.store.findById(this.sessionId)).isNull(); assertThat(this.store.findById(other)).isNull(); assertThat(version(this.userId)).isEqualTo(2); assertThat(hash(this.userId)).isEqualTo(hash);
		assertThat(get("/api/admin/me", administrator.session()).statusCode()).isEqualTo(200);
		assertThat(response.headers().allValues("Set-Cookie")).noneMatch(value -> value.contains("Max-Age=0"));
		assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue(); assertThat(new IdentityAccessTokenVerifier(this.access, "https://iam.example").verify(tokens.getAccessToken().getTokenValue())).isEmpty();
		assertThat(force(this.userId, administrator.session(), otp).statusCode()).isEqualTo(400); assertThat(revocationCount()).isEqualTo(1);
		var event = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='all_sessions_revoked'").query().singleRow();
		assertThat(event).containsEntry("target_user_id", this.userId).containsEntry("actor", "user:" + administrator.factor().userId()).containsEntry("source", "browser:admin-user-sessions");
		assertThat(event.toString()).doesNotContain(administrator.session(), this.sessionId, this.secret, otp);
	}

	@Test
	void anUnknownTargetRollsBackTotpConsumptionAndCanBeCorrectedWithTheSameCode() throws Exception {
		var administrator = administrator(); long used = lastStep(administrator.factor()); String otp = freshCode(administrator.factor());
		assertThat(force(UUID.randomUUID(), administrator.session(), otp).statusCode()).isEqualTo(404); assertThat(lastStep(administrator.factor())).isEqualTo(used); assertThat(revocationCount()).isZero();
		assertThat(force(this.userId, administrator.session(), otp).statusCode()).isEqualTo(204); assertThat(lastStep(administrator.factor())).isGreaterThan(used);
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending", "disabled", "no-sessions" })
	void existingTargetsMayBeForcedOfflineWithoutChangingTheirAccountState(String state) throws Exception {
		var administrator = administrator(); UUID target = this.userId;
		if (state.equals("pending")) { target=this.users.create("pending", "Pending", AUDIT).id(); }
		else if (state.equals("disabled")) { this.states.disable(target, AUDIT); }
		else { this.jdbc.sql("DELETE FROM iam_browser_session WHERE principal_name=:id").param("id", target.toString()).update(); }
		var before = this.users.findById(target);
		assertThat(force(target, administrator.session(), freshCode(administrator.factor())).statusCode()).isEqualTo(204);
		assertThat(this.users.findById(target)).isEqualTo(before); assertThat(revocationCount()).isEqualTo(1);
	}

	@Test
	void theSoleAdministratorMayEndTheirSessionsWithoutLosingMembershipOrFactors() throws Exception {
		var administrator = administrator(); UUID actor = administrator.factor().userId(); long version = version(actor); String hash = hash(actor);
		var response = force(actor, administrator.session(), freshCode(administrator.factor())); assertThat(response.statusCode()).as(response.body()).isEqualTo(204);
		assertThat(response.headers().allValues("Set-Cookie")).anyMatch(value -> value.startsWith("__Host-IAMSESSION=") && value.contains("Max-Age=0"));
		assertThat(this.store.findById(administrator.session())).isNull(); assertThat(version(actor)).isEqualTo(version + 1); assertThat(hash(actor)).isEqualTo(hash);
		assertThat(this.jdbc.sql("SELECT user_id FROM iam_administrator").query(UUID.class).list()).containsExactly(actor);
		assertThat(this.jdbc.sql("SELECT status FROM iam_user_totp WHERE user_id=:id").param("id", actor).query(String.class).single()).isEqualTo("active");
		assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isEqualTo(1);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='browser_session_ended'").query(Long.class).single()).isZero();
		assertThat(login("rootadmin")).isNotBlank();
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-suppressed", "audit-altered", "audit-deferred", "epoch-suppressed", "save-suppressed", "self-audit-deferred" })
	void mandatoryFailuresRollBackTargetRevocationActorTotpAndBothSessions(String failure) throws Exception {
		var administrator = administrator(); UUID target = failure.startsWith("self") ? administrator.factor().userId() : this.userId;
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code))); var grant = stored(code);
		String csrf = csrf(administrator.session()); long step = lastStep(administrator.factor()); long version = version(target);
		boolean deferred = failure.endsWith("deferred"); String table = failure.equals("epoch-suppressed") ? "iam_password" : failure.equals("save-suppressed") ? "iam_browser_session" : "iam_security_audit";
		String operation = table.equals("iam_security_audit") ? "INSERT" : "UPDATE";
		String body = failure.equals("audit-suppressed") ? "IF NEW.action='all_sessions_revoked' THEN RETURN NULL; END IF; RETURN NEW;"
				: failure.equals("audit-altered") ? "IF NEW.action='all_sessions_revoked' THEN NEW.source='altered'; END IF; RETURN NEW;"
				: failure.endsWith("suppressed") ? "RETURN OLD;" : "RAISE EXCEPTION 'private forced-offline fault';";
		fault(table, (deferred ? "AFTER " : "BEFORE ") + operation, body, deferred);
		var response = send(path(target), "POST", administrator.session(), "code=" + freshCode(administrator.factor()), "application/x-www-form-urlencoded", csrf);
		assertThat(response.statusCode()).as(response.body()).isEqualTo(503); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(response.body()).doesNotContain("private forced-offline fault", this.secret, administrator.session());
		assertThat(version(target)).isEqualTo(version); assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(this.store.findById(administrator.session())).isNotNull();
		assertThat(stored(code)).isEqualTo(grant); assertThat(lastStep(administrator.factor())).isEqualTo(step); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "ordinary", "missing-csrf", "other-csrf", "replayed-totp", "invalid-totp", "missing-totp" })
	void authorizationMfaAndCsrfCannotBeBypassed(String type) throws Exception {
		var administrator = administrator(); String cookie = type.equals("ordinary") ? this.sessionId : type.equals("password") ? login("rootadmin") : administrator.session();
		String csrf = type.equals("missing-csrf") ? null : csrf(type.equals("other-csrf") ? this.sessionId : cookie);
		String otp = type.equals("missing-totp") ? "" : type.equals("invalid-totp") ? "invalid" : type.equals("replayed-totp") ? otp(administrator.factor(), lastStep(administrator.factor())) : freshCode(administrator.factor());
		var response = send(path(this.userId), "POST", cookie, "code=" + otp, "application/x-www-form-urlencoded", csrf);
		assertThat(response.statusCode()).isEqualTo(Set.of("replayed-totp", "invalid-totp", "missing-totp").contains(type) ? 400 : 403);
		assertThat(version(this.userId)).isEqualTo(1); assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "query", "extra-field", "duplicate-code", "malformed-id", "GET", "DELETE", "PATCH", "json" })
	void exactRequestShapeIsEnforcedBeforeAnyRevocationOrTotpConsumption(String type) throws Exception {
		var administrator = administrator(); String target = path(this.userId); String body = "code=" + freshCode(administrator.factor()); long before = lastStep(administrator.factor());
		if (type.equals("query")) { target+="?userId=other"; } if (type.equals("extra-field")) { body+="&actor=other"; }
		if (type.equals("duplicate-code")) { body+="&code=000000"; } if (type.equals("malformed-id")) { target=target.replace(this.userId.toString(), "bad"); }
		String method = Set.of("GET", "DELETE", "PATCH").contains(type) ? type : "POST";
		var response = send(target, method, administrator.session(), body, type.equals("json") ? "application/json" : "application/x-www-form-urlencoded", csrf(administrator.session()));
		assertThat(response.statusCode()).isEqualTo(type.equals("json") ? 415 : method.equals("POST") ? 400 : 403);
		assertThat(lastStep(administrator.factor())).isEqualTo(before); assertThat(version(this.userId)).isEqualTo(1); assertThat(revocationCount()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "idle", "absolute", "mfa" })
	void expiryDuringSelfRevocationCannotBypassAnyOriginalAuthenticationDeadline(String type) throws Exception {
		var administrator = administrator(); var original = administratorContext(administrator); long step = lastStep(administrator.factor()); long version = version(original.actorId());
		long deadline = System.currentTimeMillis() + 800;
		long passwordTime = type.equals("absolute") ? deadline - 28_800_000 : type.equals("mfa") ? deadline - 901_000 : original.authenticatedAt();
		var evidence = new IdentityAdministratorAuthentication(original.actorId(), original.management().factorId(), original.credentialVersion(), passwordTime,
				type.equals("mfa") ? Instant.ofEpochMilli(deadline - 900_000) : original.management().verifiedAt());
		var stored = this.store.findById(administrator.session()); stored.setAttribute("iam.authenticatedAt", passwordTime); stored.setAttribute("iam.administratorAuthentication", evidence); this.store.save(stored);
		var context = administratorContext(administrator);
		if (type.equals("idle")) { this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", deadline).param("id", administrator.session()).update(); }
		assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(context, context.actorId(), freshCode(administrator.factor()), () ->
				await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() >= deadline)));
		assertThat(version(context.actorId())).isEqualTo(version); assertThat(lastStep(administrator.factor())).isEqualTo(step); assertThat(this.store.findById(administrator.session())).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void intentionalEpochAdvancementCannotHideTheLossOfTheVerifiedFactor() throws Exception {
		var administrator = administrator(); var context = administratorContext(administrator); long step = lastStep(administrator.factor()); long version = version(context.actorId());
		assertThatIllegalStateException().isThrownBy(() -> this.management.revokeAll(context, context.actorId(), freshCode(administrator.factor()), () ->
				assertThat(this.jdbc.sql("UPDATE iam_user_totp SET status='pending',activated_at=NULL,last_used_step=NULL WHERE user_id=:id").param("id", context.actorId()).update()).isEqualTo(1)));
		assertThat(version(context.actorId())).isEqualTo(version); assertThat(lastStep(administrator.factor())).isEqualTo(step); assertThat(this.store.findById(administrator.session())).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void targetLockWaitCannotUseAnAdministratorWhoLostMembershipWhileWaiting() throws Exception {
		var administrator = administrator(); var context = administratorContext(administrator); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
				this.jdbc.sql("DELETE FROM iam_administrator WHERE user_id=:id").param("id", context.actorId()).update(); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var removal = executor.submit(() -> this.management.revokeAll(context, this.userId, freshCode(administrator.factor()), () -> fail("Revoked administrator saved")));
			try { await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%iam_user%'").query(Long.class).single() > 0); }
			finally { release.countDown(); }
			writer.get(10, TimeUnit.SECONDS); assertThat(removal.get(10, TimeUnit.SECONDS).status()).isEqualTo(IdentityUserSessionManagement.Status.FORBIDDEN);
		}
		assertThat(version(this.userId)).isEqualTo(1); assertThat(this.store.findById(this.sessionId)).isNotNull(); assertThat(revocationCount()).isZero();
	}

	@Test
	void swaggerDocumentsTheTargetBoundMfaOperationWithoutCredentialResponses() throws Exception {
		var response = get("/v3/api-docs", this.sessionId); assertThat(response.statusCode()).isEqualTo(200);
		var route = JSON.readTree(response.body()).path("paths").path("/api/admin/users/{userId}/sessions/revoke-all");
		assertThat(route.propertyNames()).containsExactly("post"); assertThat(route.path("post").path("operationId").asText()).isEqualTo("revokeAllUserSessions");
		assertThat(route.path("post").path("responses").path("204").has("content")).isFalse();
		assertThat(route.path("post").path("requestBody").path("content").has("application/x-www-form-urlencoded")).isTrue();
		assertThat(route.path("post").path("description").asText()).contains("TOTP", "分页", "自己", "离线");
	}

	private Administrator administrator() throws Exception {
		UUID id = this.administrators.createCandidate("rootadmin", "Administrator", PASSWORD, AUDIT);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(id, PASSWORD, totpContext()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(id, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), totpContext()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=last_used_step-1 WHERE user_id=:id").param("id", id).update();
		String cookie = login("rootadmin"); var response = send("/admin/mfa", "POST", cookie, "code=" + otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), "application/x-www-form-urlencoded", csrf(cookie));
		assertThat(response.statusCode()).as(response.body()).isEqualTo(204); return new Administrator(factor, cookie(response));
	}
	private IdentityAdministratorContext administratorContext(Administrator administrator) {
		var session = this.store.findById(administrator.session());
		return new IdentityAdministratorContext(administrator.factor().userId(), session.getId(), session.getAttribute("iam.credentialVersion"), session.getAttribute("iam.authenticatedAt"),
				session.getAttribute("iam.administratorAuthentication"), totpContext());
	}
	private String login(String user) throws Exception {
		var page = get("/api/csrf", null); String cookie = cookie(page); String token = JSON.readTree(page.body()).path("token").asText();
		var response = send("/login", "POST", cookie, JSON.writeValueAsString(Map.of("username", user, "password", PASSWORD)), "application/json", token);
		assertThat(response.statusCode()).as(response.body()).isEqualTo(204); return cookie(response);
	}
	private HttpResponse<String> force(UUID id, String session, String code) throws Exception { return send(path(id), "POST", session, "code=" + code, "application/x-www-form-urlencoded", csrf(session)); }
	private static String path(UUID id) { return "/api/admin/users/" + id + "/sessions/revoke-all"; }
	private long version(UUID id) { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id=:id").param("id", id).query(Long.class).single(); }
	private String hash(UUID id) { return this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id=:id").param("id", id).query(String.class).single(); }
	private long revocationCount() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='all_sessions_revoked'").query(Long.class).single(); }
	private long lastStep(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single(); }
	private String csrf(String cookie) throws Exception { var response = get("/api/csrf", cookie); assertThat(response.statusCode()).isEqualTo(200); return JSON.readTree(response.body()).path("token").asText(); }
	private static String cookie(HttpResponse<String> response) { return response.headers().allValues("Set-Cookie").stream().filter(value -> value.startsWith("__Host-IAMSESSION=")).findFirst().orElseThrow().split(";", 2)[0].substring("__Host-IAMSESSION=".length()); }
	private HttpResponse<String> get(String path, String cookie) throws Exception { return send(path, "GET", cookie, null, null, null); }
	private HttpResponse<String> send(String path, String method, String cookie, String body, String contentType, String csrf) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (cookie != null) { request.header("Cookie", "__Host-IAMSESSION=" + cookie); } if (csrf != null) { request.header("X-CSRF-TOKEN", csrf); } if (contentType != null) { request.header("Content-Type", contentType); }
		try (var client = client()) { return client.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private static TotpAuthenticationContext totpContext() { return new TotpAuthenticationContext("internal:forced-offline-test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-forced-offline-test-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key);
			Files.write(path, key); java.util.Arrays.fill(key, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private record Administrator(IdentityTotpEnrollment factor, String session) {
		@Override public String toString() { return "Administrator[REDACTED]"; }
	}
}
