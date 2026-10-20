package com.ixayda.iam.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.service.IdentityAccessTokens;

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

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityProtocolHttpIntegrationTests extends IdentityProtocolTestSupport {

	private static final String ENDPOINT = "/oauth2/token";
	@LocalServerPort private int port;
	@Autowired private IdentityAccessTokens accessTokens;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true);
		registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@Test
	void codeExchangeUsesTheFixedIssuerAndPublishesOnlyCommittedNativeTokensWithoutASession() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access"));
		var sessions = sessionSnapshot();
		var response = token(codeBody(code));
		var json = success(response);
		var stored = stored(code).authorization();
		assertThat(json.properties().stream().map(Map.Entry::getKey)).containsExactlyInAnyOrder("access_token", "token_type", "expires_in", "scope", "refresh_token", "id_token");
		assertThat(json.path("access_token").asText()).isEqualTo(stored.getAccessToken().getToken().getTokenValue());
		assertThat(json.path("id_token").asText()).isEqualTo(stored.getToken(org.springframework.security.oauth2.core.oidc.OidcIdToken.class).getToken().getTokenValue());
		assertThat(json.path("refresh_token").asText()).isEqualTo(stored.getRefreshToken().getToken().getTokenValue());
		assertThat(json.path("expires_in").asLong()).isBetween(1L, 300L);
		assertThat(verified(json.path("access_token").asText(), "at+jwt").getIssuer()).isEqualTo("https://iam.example");
		assertThat(verifier().verify(json.path("access_token").asText())).isPresent();
		assertThat(sessionSnapshot()).isEqualTo(sessions);
		assertThat(tokenAudits()).singleElement().satisfies(audit -> {
			assertThat(audit.get("action")).isEqualTo("tokens_issued"); assertThat(audit.get("actor")).isEqualTo("client:" + this.clientId);
		});
		assertNoSecretsInAudit(code, json.path("access_token").asText(), json.path("refresh_token").asText());
	}

	@Test
	void nonOfflineCodeExchangeDoesNotReturnOrCreateRefreshState() throws Exception {
		String code = code(Set.of("openid")); var response = success(token(codeBody(code)));
		assertThat(response.has("refresh_token")).isFalse(); assertThat(stored(code).authorization().getRefreshToken()).isNull();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_family").query(Long.class).single()).isZero();
	}

	@Test
	void refreshRotatesOfflineCredentialsAfterBrowserLogoutAndCanCloseTheFamilyWithoutExpandingScopes() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access"));
		var issued = success(token(codeBody(code)));
		this.store.deleteById(this.sessionId);
		String body = refreshBody(issued.path("refresh_token").asText());
		var refreshed = success(token(body));
		assertThat(refreshed.path("refresh_token").asText()).isNotEqualTo(issued.path("refresh_token").asText());
		assertThat(verifier().verify(issued.path("access_token").asText())).isEmpty();
		assertThat(verifier().verify(refreshed.path("access_token").asText())).isPresent();
		var narrowed = success(token(refreshBody(refreshed.path("refresh_token").asText()) + "&scope=profile"));
		assertThat(narrowed.path("scope").asText()).isEqualTo("profile"); assertThat(narrowed.has("refresh_token")).isFalse(); assertThat(narrowed.has("id_token")).isFalse();
		assertThat(verifier().verify(narrowed.path("access_token").asText()).orElseThrow().scopes()).containsExactly("profile");
		assertThat(this.refresh.findByAuthorization(stored(code).authorization()).orElseThrow().status()).isEqualTo(IdentityRefreshFamily.Status.CLOSED);
	}

	@ParameterizedTest
	@ValueSource(strings = { "code", "refresh" })
	void provenCredentialReplayCommitsRevocationBeforeReturningAnError(String credential) throws Exception {
		String code = code(Set.of("openid", "offline_access")); var issued = success(token(codeBody(code)));
		String bearer = issued.path("access_token").asText();
		String body = codeBody(code);
		if (credential.equals("refresh")) {
			body = refreshBody(issued.path("refresh_token").asText()); bearer = success(token(body)).path("access_token").asText();
		}
		error(token(body), 400, "invalid_grant");
		assertThat(verifier().verify(bearer)).isEmpty();
		assertThat(this.refresh.findByAuthorization(stored(code).authorization()).orElseThrow().status())
				.isEqualTo(IdentityRefreshFamily.Status.QUARANTINED);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action=:action")
				.param("action", credential.equals("code") ? "authorization_code_replayed" : "refresh_token_replayed").query(Long.class).single()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "code", "refresh" })
	void concurrentUseHasOneWinnerAndQuarantinesOrRevokesTheWinnerWhenItsParentIsReplayed(String credential) throws Exception {
		String code = code(Set.of("openid", "offline_access")); String body = codeBody(code);
		if (credential.equals("refresh")) { body = refreshBody(success(token(body)).path("refresh_token").asText()); }
		var start = new CountDownLatch(1); String requestBody = body;
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			var first = executor.submit(() -> { awaitLatch(start); return token(requestBody); });
			var second = executor.submit(() -> { awaitLatch(start); return token(requestBody); });
			start.countDown(); var responses = List.of(first.get(20, TimeUnit.SECONDS), second.get(20, TimeUnit.SECONDS));
			assertThat(responses).extracting(HttpResponse::statusCode).containsExactlyInAnyOrder(200, 400);
			var winner = success(responses.stream().filter(response -> response.statusCode() == 200).findFirst().orElseThrow());
			error(responses.stream().filter(response -> response.statusCode() == 400).findFirst().orElseThrow(), 400, "invalid_grant");
			assertThat(verifier().verify(winner.path("access_token").asText())).isEmpty();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "grant_type", "code", "code_verifier", "redirect_uri", "scope", "unknown" })
	void duplicateFormFieldsAreRejectedBeforeClientProofOrGrantConsumption(String duplicate) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		String suffix = Set.of("scope", "unknown").contains(duplicate) ? "&" + duplicate + "=&" + duplicate + "=" : "&" + duplicate + "=";
		error(token(codeBody(code) + suffix), 400, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "grant_type", "code", "code_verifier", "private-query-value" })
	void queryParametersCannotBeMergedIntoAProtocolPost(String field) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(send(ENDPOINT + "?" + field + "=private-query", "POST", "application/x-www-form-urlencoded", basic(), codeBody(code), Map.of()), 400, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "resource", "audience", "scope" })
	void grantExchangeCannotExpandOriginalParameters(String parameter) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(token(codeBody(code) + "&" + parameter + "=private-expansion"), 400, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "client_id", "client_secret", "client_assertion", "client_assertion_type" })
	void bodyAuthenticationCannotBeCombinedWithBasicOrUsedAsAnAlternative(String parameter) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(token(codeBody(code) + "&" + parameter + "=private-body-proof"), 400, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "bearer", "wrong-secret", "foreign-client", "malformed" })
	void onlyBasicAuthenticationWithTheCurrentOriginalClientCanReachTheGrant(String proof) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		String header = switch (proof) {
			case "missing" -> null;
			case "bearer" -> "Bearer private-bearer";
			case "wrong-secret" -> basic(this.clientId.toString(), "private-wrong-secret");
			case "foreign-client" -> basic(UUID.randomUUID().toString(), this.secret);
			case "malformed" -> "Basic **invalid**";
			default -> throw new IllegalStateException();
		};
		var response = send(ENDPOINT, "POST", "application/x-www-form-urlencoded", header, codeBody(code), Map.of());
		error(response, proof.equals("malformed") ? 400 : 401, proof.equals("malformed") ? "invalid_request" : "invalid_client");
		if (!proof.equals("malformed")) { assertThat(response.headers().firstValue("WWW-Authenticate")).contains("Basic realm=\"iam/token\""); }
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
		assertNoSecretsInAudit(code, "private-bearer", "private-wrong-secret");
	}

	@ParameterizedTest
	@ValueSource(strings = { "verifier", "redirect", "code", "cross-client" })
	void invalidCodeProofDoesNotConsumeOrRevokeTheOriginalGrant(String invalid) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot(); String header = basic();
		String body = switch (invalid) {
			case "verifier" -> codeBody(code).replace(VERIFIER, "a".repeat(43));
			case "redirect" -> codeBody(code).replace(encode(REDIRECT), encode("https://attacker.example/callback"));
			case "code" -> codeBody("unrecognized-code");
			default -> codeBody(code);
		};
		if (invalid.equals("cross-client")) {
			var other = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
			header = basic(other.client().id().toString(), other.secret());
		}
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", header, body, Map.of()), 400, "invalid_grant");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
		success(token(codeBody(code)));
	}

	@ParameterizedTest
	@ValueSource(strings = { "password", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange" })
	void unsupportedGrantTypesHaveNoNativeProviderFallback(String grant) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(token("grant_type=" + encode(grant) + "&code=" + encode(code)), 400, "unsupported_grant_type");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "text/plain", "application/json", "application/*", "*/*", "application/x-www-form-urlencoded;charset=ISO-8859-1" })
	void protocolPostsRequireUtf8FormEncoding(String mediaType) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(send(ENDPOINT, "POST", mediaType.isEmpty() ? null : mediaType, basic(), codeBody(code), Map.of()), 415, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE" })
	void theBackChannelOnlyAllowsPostAndNeverRedirectsOtherMethods(String method) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		var response = send(ENDPOINT, method, null, basic(), "", Map.of());
		assertThat(response.statusCode()).isEqualTo(405); assertThat(response.headers().firstValue("Allow")).contains("POST");
		assertThat(response.headers().firstValue("Location")).isEmpty(); assertSecurityHeaders(response);
		if (!method.equals("HEAD")) { error(response, 405, "invalid_request"); }
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@Test
	void browserCookiesAndBusinessBearersCannotAuthenticateTheOtherSecurityChain() throws Exception {
		String code = code(Set.of("openid")); String cookie = "__Host-IAMSESSION=" + this.sessionId;
		var before = sessionSnapshot();
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", null, codeBody(code), Map.of("Cookie", cookie)), 401, "invalid_client");
		assertThat(sessionSnapshot()).isEqualTo(before);
		var tokens = success(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", basic(), codeBody(code), Map.of("Cookie", cookie)));
		assertThat(sessionSnapshot()).isEqualTo(before);
		var management = send("/api/admin/me", "GET", null, "Bearer " + tokens.path("access_token").asText(), "", Map.of());
		assertThat(management.statusCode()).isEqualTo(401);
		assertThat(send("/api/me", "GET", null, basic(), "", Map.of()).statusCode()).isEqualTo(401);
		assertThat(send("/api/me", "GET", null, null, "", Map.of("Cookie", cookie)).statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit-suppressed", "audit-unavailable", "commit" })
	void failedSuccessAuditOrCommitCannotPublishTokens(String fault) throws Exception {
		String code = code(Set.of("openid", "offline_access")); var before = protocolSnapshot();
		switch (fault) {
			case "audit-suppressed" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_issued' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-unavailable" -> fault("iam_security_audit", "BEFORE INSERT", "RAISE EXCEPTION 'private protocol test fault';", false);
			default -> fault("oauth2_authorization", "AFTER UPDATE", "RAISE EXCEPTION 'private protocol test fault';", true);
		}
		error(token(codeBody(code)), 503, "server_error");
		assertThat(protocolSnapshot()).isEqualTo(before);
		this.jdbc.sql("DROP FUNCTION exchange_test_fault() CASCADE").update();
		success(token(codeBody(code)));
	}

	@Test
	void failedEarlyRejectionAuditReturnsUnavailableAndLeavesTheCodeUsable() throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='token_request_rejected' THEN RETURN NULL; END IF; RETURN NEW;", false);
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", null, codeBody(code), Map.of()), 503, "server_error");
		assertThat(protocolSnapshot()).isEqualTo(before);
		this.jdbc.sql("DROP FUNCTION exchange_test_fault() CASCADE").update(); success(token(codeBody(code)));
	}

	@Test
	void sharedIngressRejectsOversizedBodiesWithAProtocolErrorAndNeverConsumesTheCode() throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(token(codeBody(code) + "&unknown=" + "x".repeat(8192)), 413, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before);
	}

	@Test
	void anOversizedChunkedFormCannotSlipThroughAfterTheValidGrantFields() throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		byte[] body = (codeBody(code) + "&unknown=" + "x".repeat(8192)).getBytes(StandardCharsets.UTF_8);
		try (HttpClient client = client()) {
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + ENDPOINT)).timeout(Duration.ofSeconds(20))
					.header("Content-Type", "application/x-www-form-urlencoded").header("Authorization", basic())
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(body))).build();
			var response = client.send(request, HttpResponse.BodyHandlers.ofString());
			assertThat(response.statusCode()).isIn(400, 413); error(response, response.statusCode(), "invalid_request");
		}
		assertThat(protocolSnapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "Authorization", "DPoP" })
	void duplicateAuthorizationHeadersAndUnsupportedProofHeadersAreRejected(String header) throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", basic(), codeBody(code), Map.of(header, "private-extra-proof")), 400, "invalid_request");
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection();
	}

	@Test
	void suppliedForwardingHeadersCannotChangeThePersistedIssuer() throws Exception {
		String code = code(Set.of("openid"));
		var result = success(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", basic(), codeBody(code),
				Map.of("Forwarded", "proto=http;host=attacker.example", "X-Forwarded-Host", "attacker.example", "X-Forwarded-Proto", "http")));
		assertThat(verified(result.path("access_token").asText(), "at+jwt").getIssuer()).isEqualTo("https://iam.example");
		assertThat(verified(result.path("id_token").asText(), "JWT").getIssuer()).isEqualTo("https://iam.example");
	}

	@Test
	void aNativeStoreOutageReturnsUnavailableWithoutConsumingOrPublishingTheGrant() throws Exception {
		String code = code(Set.of("openid")); var before = protocolSnapshot();
		this.jdbc.sql("ALTER TABLE oauth2_authorization RENAME TO isolated_unavailable_authorization").update();
		try { error(token(codeBody(code)), 503, "server_error"); }
		finally { this.jdbc.sql("ALTER TABLE isolated_unavailable_authorization RENAME TO oauth2_authorization").update(); }
		assertThat(protocolSnapshot()).isEqualTo(before); assertSingleRequestRejection(); success(token(codeBody(code)));
	}


	@ParameterizedTest
	@ValueSource(strings = { "GET", "POST" })
	void userInfoProjectsOnlyCurrentScopePermittedClaimsWithoutReadingBrowserState(String method) throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile"))))).path("access_token").asText();
		var sessions = sessionSnapshot(); var grants = protocolSnapshot();
		this.jdbc.sql("UPDATE iam_user SET display_name='Current profile name' WHERE id=:id").param("id", this.userId).update();
		var response = send("/userinfo", method, null, "Bearer " + bearer, "", Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
		var claims = userInfoSuccess(response);
		assertThat(claims.properties()).extracting(Map.Entry::getKey).containsExactlyInAnyOrder("sub", "name", "preferred_username");
		assertThat(claims.path("sub").asText()).isEqualTo(this.userId.toString());
		assertThat(claims.path("name").asText()).isEqualTo("Current profile name"); assertThat(claims.path("preferred_username").asText()).isEqualTo("alice");
		assertThat(sessionSnapshot()).isEqualTo(sessions); assertThat(protocolSnapshot()).isEqualTo(grants); assertThat(userInfoAudits()).isEmpty();
	}

	@Test
	void userInfoUsesActualScopesRatherThanClientConfigurationOrTheOriginalAuthorization() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access")); var issued = success(token(codeBody(code)));
		var narrowed = success(token(refreshBody(issued.path("refresh_token").asText()) + "&scope=openid%20offline_access"));
		var claims = userInfoSuccess(userInfo(narrowed.path("access_token").asText()));
		assertThat(claims.properties()).containsExactly(Map.entry("sub", new JsonMapper().getNodeFactory().stringNode(this.userId.toString())));
		var withoutOpenId = success(token(refreshBody(narrowed.path("refresh_token").asText()) + "&scope=offline_access"));
		var response = userInfo(withoutOpenId.path("access_token").asText()); error(response, 403, "insufficient_scope");
		assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow()).contains("Bearer ", "error=\"insufficient_scope\"", "scope=\"openid\"");
		assertThat(userInfoAudits()).singleElement().satisfies(audit -> {
			assertThat(audit.get("actor")).isEqualTo("user:" + this.userId); assertThat(audit.get("target_user_id")).isEqualTo(this.userId);
		});
	}

	@Test
	void openIdAloneDoesNotReturnConfiguredProfileClaimsAndBrowserLogoutDoesNotEndAnApplicationGrant() throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid"))))).path("access_token").asText();
		this.store.deleteById(this.sessionId);
		assertThat(userInfoSuccess(userInfo(bearer)).properties()).extracting(Map.Entry::getKey).containsExactly("sub");
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "basic", "cookie" })
	void browserOrClientAuthenticationCannotReplaceTheUserInfoBearerChallenge(String proof) throws Exception {
		var sessions = sessionSnapshot();
		var response = send("/userinfo", "GET", null, proof.equals("basic") ? basic() : null, "",
				proof.equals("cookie") ? Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId) : Map.of());
		assertThat(response.statusCode()).isEqualTo(401); assertThat(response.body()).isEmpty(); assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("WWW-Authenticate")).contains("Bearer realm=\"iam/userinfo\"");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(sessionSnapshot()).isEqualTo(sessions);
		assertAnonymousUserInfoRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "id_token", "refresh_token", "altered", "malformed" })
	void userInfoRejectsOtherCredentialPurposesAndInvalidBearerProofs(String proof) throws Exception {
		var issued = success(token(codeBody(code(Set.of("openid", "offline_access")))));
		String bearer = switch (proof) {
			case "altered" -> issued.path("access_token").asText().replaceFirst(".$", "!");
			case "malformed" -> "private-not-a-jwt";
			default -> issued.path(proof).asText();
		};
		var response = userInfo(bearer); error(response, 401, "invalid_token");
		assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow()).contains("Bearer ", "error=\"invalid_token\"");
		assertAnonymousUserInfoRejection(); assertNoSecretsInAudit(bearer, issued.path("id_token").asText(), issued.path("refresh_token").asText());
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-disabled", "credential", "client-secret", "client-disabled", "client-transferred", "resource", "resource-disabled", "role", "role-disabled", "assignment" })
	void userInfoRechecksTheCurrentUserAndApplicationGrantRatherThanTrustingAnUnexpiredSignature(String mutation) throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile", "offline_access"))))).path("access_token").asText();
		mutate(mutation); error(userInfo(bearer), 401, "invalid_token"); assertAnonymousUserInfoRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "query", "body", "duplicate", "dpop", "chunked" })
	void userInfoRejectsAmbiguousOrAlternateBearerTransportBeforeGrantUse(String transport) throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile"))))).path("access_token").asText();
		var sessions = sessionSnapshot(); var grants = protocolSnapshot();
		HttpResponse<String> response;
		if (transport.equals("chunked")) {
			try (var client = client()) {
				var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + "/userinfo")).timeout(Duration.ofSeconds(20))
						.header("Authorization", "Bearer " + bearer).POST(HttpRequest.BodyPublishers.ofInputStream(() -> new java.io.ByteArrayInputStream(new byte[] { 1 }))).build();
				response = client.send(request, HttpResponse.BodyHandlers.ofString());
			}
		}
		else {
			var headers = transport.equals("duplicate") ? Map.of("Authorization", "Bearer private-duplicate") : transport.equals("dpop") ? Map.of("DPoP", "private-proof") : Map.<String, String>of();
			response = send("/userinfo" + (transport.equals("query") ? "?access_token=private-query-token" : ""), "POST", "application/x-www-form-urlencoded",
					"Bearer " + bearer, transport.equals("body") ? "access_token=private-body-token" : "", headers);
		}
		error(response, 400, "invalid_request"); assertAnonymousUserInfoRejection();
		assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow()).contains("Bearer ", "error=\"invalid_request\"");
		assertThat(sessionSnapshot()).isEqualTo(sessions); assertThat(protocolSnapshot()).isEqualTo(grants);
		userInfoSuccess(userInfo(bearer)); assertNoSecretsInAudit(bearer, "private-body-token", "private-query-token", "private-proof", "private-duplicate");
	}

	@ParameterizedTest
	@ValueSource(strings = { "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE" })
	void userInfoOnlyAllowsGetAndPostWithoutCookieCsrfOrRedirects(String method) throws Exception {
		var response = send("/userinfo", method, null, null, "", Map.of());
		assertThat(response.statusCode()).isEqualTo(405); assertThat(response.headers().firstValue("Allow")).contains("GET, POST");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty(); assertSecurityHeaders(response);
		if (!method.equals("HEAD")) { error(response, 405, "invalid_request"); }
		assertAnonymousUserInfoRejection();
	}

	@ParameterizedTest
	@ValueSource(strings = { "suppressed", "altered", "unavailable" })
	void aFailedMandatoryUserInfoDenialAuditReturnsUnavailableRatherThanAnUnauditedChallenge(String failure) throws Exception {
		String body = switch (failure) {
			case "suppressed" -> "IF NEW.action='user_info_rejected' THEN RETURN NULL; END IF; RETURN NEW;";
			case "altered" -> "IF NEW.action='user_info_rejected' THEN NEW.source='altered'; END IF; RETURN NEW;";
			default -> "RAISE EXCEPTION 'private userinfo audit fault';";
		};
		fault("iam_security_audit", "BEFORE INSERT", body, false);
		error(userInfo("private-invalid-token"), 503, "server_error"); assertThat(userInfoAudits()).isEmpty();
		this.jdbc.sql("DROP FUNCTION exchange_test_fault() CASCADE").update();
	}

	@Test
	void userInfoDoesNotNeedTheBrowserSessionTableEvenWhenItsCookieIsSupplied() throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile"))))).path("access_token").asText();
		this.jdbc.sql("ALTER TABLE iam_browser_session RENAME TO isolated_userinfo_browser_session").update();
		try { userInfoSuccess(send("/userinfo", "POST", null, "Bearer " + bearer, "", Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId))); }
		finally { this.jdbc.sql("ALTER TABLE isolated_userinfo_browser_session RENAME TO iam_browser_session").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "oauth2_authorization", "iam_user" })
	void userInfoDependencyFailuresNeverReturnClaimsOrExposeInternalExceptions(String table) throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile"))))).path("access_token").asText();
		this.jdbc.sql("ALTER TABLE " + table + " RENAME TO isolated_userinfo_unavailable").update();
		try { error(userInfo(bearer), 503, "server_error"); }
		finally { this.jdbc.sql("ALTER TABLE isolated_userinfo_unavailable RENAME TO " + table).update(); }
		assertAnonymousUserInfoRejection(); userInfoSuccess(userInfo(bearer));
	}

	@ParameterizedTest
	@ValueSource(strings = { "profile", "disable" })
	void userInfoWaitingForASubjectWriterUsesItsCommittedProfileAndSecurityState(String mutation) throws Exception {
		String bearer = success(token(codeBody(code(Set.of("openid", "profile"))))).path("access_token").asText();
		var postgres = this.context.getBean(org.testcontainers.postgresql.PostgreSQLContainer.class);
		try (var connection = java.sql.DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			connection.setAutoCommit(false);
			try (var lock = connection.prepareStatement("SELECT id FROM iam_user WHERE id=? FOR UPDATE")) { lock.setObject(1, this.userId); lock.executeQuery().close(); }
			var pending = executor.submit(() -> userInfo(bearer));
			try {
				org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id=%FOR SHARE%'").query(Long.class).single() > 0);
				String sql = mutation.equals("profile") ? "UPDATE iam_user SET display_name='Committed current profile' WHERE id=?" : "UPDATE iam_user SET status='disabled' WHERE id=?";
				try (var update = connection.prepareStatement(sql)) { update.setObject(1, this.userId); update.executeUpdate(); }
			}
			finally { connection.commit(); }
			var response = pending.get(15, TimeUnit.SECONDS);
			if (mutation.equals("profile")) { assertThat(userInfoSuccess(response).path("name").asText()).isEqualTo("Committed current profile"); }
			else { error(response, 401, "invalid_token"); }
		}
	}

	private HttpResponse<String> userInfo(String bearer) throws Exception { return send("/userinfo", "GET", null, "Bearer " + bearer, "", Map.of()); }
	private static JsonNode userInfoSuccess(HttpResponse<String> response) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty();
		return new JsonMapper().readTree(response.body());
	}
	private List<Map<String, Object>> userInfoAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='user_info_rejected'").query().listOfRows(); }
	private void assertAnonymousUserInfoRejection() {
		assertThat(userInfoAudits()).singleElement().satisfies(audit -> {
			assertThat(audit.get("actor")).isEqualTo("anonymous"); assertThat(audit.get("target_user_id")).isNull();
			assertThat(audit.get("source")).isEqualTo("protocol:userinfo"); assertThat(audit.get("correlation_id")).isInstanceOf(UUID.class);
		});
	}

	@Test
	void publicJwkSetContainsOnlyThePersistentRsaPublicIdentityAndVerifiesIssuedHttpTokens() throws Exception {
		String code = code(Set.of("openid")); var issued = success(token(codeBody(code)));
		var response = publicKeys(Map.of());
		var set = com.nimbusds.jose.jwk.JWKSet.parse(response.body());
		assertThat(set.getKeys()).hasSize(1); var key = set.getKeys().getFirst();
		assertThat(key.toJSONObject()).containsOnlyKeys("kty", "kid", "use", "alg", "n", "e");
		assertThat(key.isPrivate()).isFalse(); assertThat(key.getKeyID()).isEqualTo(this.signing.id().toString());
		assertThat(key.getAlgorithm().getName()).isEqualTo("RS256"); assertThat(key.getKeyUse().identifier()).isEqualTo("sig");
		var rsa = key.toRSAKey().toRSAPublicKey(); assertThat(rsa).isEqualTo(this.signing.publicKey()); assertThat(rsa.getModulus().bitLength()).isEqualTo(3072);
		for (String field : List.of("access_token", "id_token")) {
			var jwt = com.nimbusds.jwt.SignedJWT.parse(issued.path(field).asText());
			assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.getKeyID()); assertThat(jwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(rsa))).isTrue();
		}
		assertThat(publicKeys(Map.of()).body()).isEqualTo(response.body());
	}

	@ParameterizedTest
	@ValueSource(strings = { "valid-cookie", "invalid-cookie", "basic", "bearer", "forwarding" })
	void publicKeysNeverReadOrChangeBrowserStateOrDependOnAuthenticationHeaders(String transport) throws Exception {
		var sessions = sessionSnapshot(); var grants = protocolSnapshot();
		Map<String, String> headers = switch (transport) {
			case "valid-cookie" -> Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId);
			case "invalid-cookie" -> Map.of("Cookie", "__Host-IAMSESSION=invalid-private-session");
			case "basic" -> Map.of("Authorization", basic());
			case "bearer" -> Map.of("Authorization", "Bearer private-business-token");
			default -> Map.of("Forwarded", "proto=http;host=attacker.example", "X-Forwarded-Host", "attacker.example");
		};
		assertThat(publicKeys(headers).body()).isEqualTo(publicKeys(Map.of()).body());
		assertThat(sessionSnapshot()).isEqualTo(sessions); assertThat(protocolSnapshot()).isEqualTo(grants);
		assertThat(tokenAudits()).isEmpty();
	}

	@Test
	void publicKeyPublicationDoesNotQueryOrDecryptEncryptedPrivateMaterial() throws Exception {
		String expected = publicKeys(Map.of()).body();
		byte[] encrypted = this.jdbc.sql("SELECT encrypted_private_key FROM iam_signing_key").query(byte[].class).single();
		this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)").update();
		try { assertThat(publicKeys(Map.of()).body()).isEqualTo(expected); }
		finally { this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=:original").param("original", encrypted).update(); }
	}

	@Test
	void aBrowserSessionStoreOutageCannotBlockAnIndependentPublicKeyRead() throws Exception {
		String expected = publicKeys(Map.of()).body();
		this.jdbc.sql("ALTER TABLE iam_browser_session RENAME TO isolated_public_key_browser_session").update();
		try { assertThat(publicKeys(Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)).body()).isEqualTo(expected); }
		finally { this.jdbc.sql("ALTER TABLE isolated_public_key_browser_session RENAME TO iam_browser_session").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "unavailable", "empty", "malformed" })
	void unavailableOrInconsistentPublicKeyStateCannotPublishAnEmptyOrTemporarySet(String fault) throws Exception {
		String expected = publicKeys(Map.of()).body();
		byte[] original = this.jdbc.sql("SELECT public_key FROM iam_signing_key").query(byte[].class).single();
		if (fault.equals("malformed")) { this.jdbc.sql("UPDATE iam_signing_key SET public_key=:value").param("value", new byte[] { 1 }).update(); }
		else {
			this.jdbc.sql("ALTER TABLE iam_signing_key RENAME TO isolated_public_key").update();
			if (fault.equals("empty")) { this.jdbc.sql("CREATE TABLE iam_signing_key (LIKE isolated_public_key INCLUDING ALL)").update(); }
		}
		try { error(send("/oauth2/jwks", "GET", null, null, "", Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)), 503, "server_error"); }
		finally {
			if (fault.equals("malformed")) { this.jdbc.sql("UPDATE iam_signing_key SET public_key=:value").param("value", original).update(); }
			else {
				if (fault.equals("empty")) { this.jdbc.sql("DROP TABLE iam_signing_key").update(); }
				this.jdbc.sql("ALTER TABLE isolated_public_key RENAME TO iam_signing_key").update();
			}
		}
		assertThat(publicKeys(Map.of()).body()).isEqualTo(expected); assertThat(tokenAudits()).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE" })
	void publicKeyPublicationOnlyAllowsGetAndDoesNotRedirectOrUseBrowserCsrf(String method) throws Exception {
		var response = send("/oauth2/jwks", method, null, null, "", Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
		assertThat(response.statusCode()).isEqualTo(405); assertThat(response.headers().firstValue("Allow")).contains("GET");
		assertThat(response.headers().firstValue("Location")).isEmpty(); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertSecurityHeaders(response);
		if (!method.equals("HEAD")) { error(response, 405, "invalid_request"); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "query", "body" })
	void publicKeyReadsDoNotAcceptQueryOrBodyParameters(String location) throws Exception {
		String suffix = location.equals("query") ? "?kid=private-requested-key" : "";
		String body = location.equals("body") ? "kid=private-requested-key" : "";
		error(send("/oauth2/jwks" + suffix, "GET", "application/x-www-form-urlencoded", null, body, Map.of()), 400, "invalid_request");
		assertThat(tokenAudits()).isEmpty();
	}

	private HttpResponse<String> publicKeys(Map<String, String> headers) throws Exception {
		var response = send("/oauth2/jwks", "GET", null, null, "", headers);
		assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty();
		return response;
	}

	@Test
	void unsupportedProtocolEndpointsAreNotPublishedByTheNativeConfigurer() throws Exception {
		for (String path : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server", "/oauth2/authorize",
				"/oauth2/introspect", "/oauth2/revoke", "/connect/register", "/oauth2/device_authorization")) {
			var response = send(path, "GET", null, basic(), "", Map.of());
			assertThat(response.statusCode()).as(path).isIn(401, 403); assertThat(response.headers().firstValue("Location")).isEmpty();
		}
	}

	@Test
	void swaggerDescribesTheEnabledProtocolWithoutBorrowingBrowserCookieAuthentication() throws Exception {
		var response = send("/v3/api-docs", "GET", null, null, "", Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
		assertThat(response.statusCode()).isEqualTo(200);
		var document = new JsonMapper().readTree(response.body());
		var operation = document.path("paths").path(ENDPOINT).path("post");
		assertThat(operation.path("operationId").asText()).isEqualTo("exchangeApplicationTokens");
		assertThat(operation.path("security").size()).isEqualTo(1); assertThat(operation.path("security").get(0).has("protocolClient")).isTrue();
		assertThat(operation.path("security").get(0).has("browserSession")).isFalse();
		assertThat(document.path("components").path("securitySchemes").path("protocolClient").path("scheme").asText()).isEqualTo("basic");
		assertThat(operation.path("requestBody").path("content").path("application/x-www-form-urlencoded").path("schema").path("oneOf").size()).isEqualTo(2);
		for (String status : List.of("400", "401", "405", "413", "415", "429", "503")) {
			assertThat(operation.path("responses").path(status).path("content").path("application/json").path("schema").path("$ref").asText())
					.isEqualTo("#/components/schemas/IdentityProtocolError");
		}
		assertThat(document.path("paths").path(ENDPOINT).has("get")).isFalse();
		var keys = document.path("paths").path("/oauth2/jwks").path("get");
		assertThat(keys.path("operationId").asText()).isEqualTo("getPublicSigningKeys");
		assertThat(keys.has("security")).isTrue(); assertThat(keys.path("security").isEmpty()).isTrue();
		assertThat(document.path("paths").path("/oauth2/jwks").has("post")).isFalse();
		assertThat(keys.path("responses").path("200").path("content").path("application/json").path("schema").path("properties").path("keys").path("items").path("properties").properties())
				.extracting(Map.Entry::getKey).containsExactlyInAnyOrder("kty", "kid", "use", "alg", "n", "e");

		for (String method : List.of("get", "post")) {
			var info = document.path("paths").path("/userinfo").path(method);
			assertThat(info.path("security").get(0).has("applicationBearer")).isTrue(); assertThat(info.path("security").get(0).has("browserSession")).isFalse();
			assertThat(info.has("requestBody")).isFalse();
			assertThat(info.path("responses").path("403").path("headers").has("WWW-Authenticate")).isTrue();
			assertThat(info.path("responses").path("200").path("content").path("application/json").path("schema").path("properties").properties())
					.extracting(Map.Entry::getKey).containsExactlyInAnyOrder("sub", "name", "preferred_username");
		}
		assertThat(document.path("components").path("securitySchemes").path("applicationBearer").path("scheme").asText()).isEqualTo("bearer");
		assertThat(document.path("info").path("description").asText()).doesNotContain("当前未提供", "随协议实现交付");
	}

	private HttpResponse<String> token(String body) throws Exception { return send(ENDPOINT, "POST", "application/x-www-form-urlencoded", basic(), body, Map.of()); }

	private HttpResponse<String> send(String path, String method, String mediaType, String authorization, String body, Map<String, String> headers) throws Exception {
		try (HttpClient client = client()) {
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
			if (mediaType != null) { request.header("Content-Type", mediaType); }
			if (authorization != null) { request.header("Authorization", authorization); }
			headers.forEach(request::header);
			return client.send(request.method(method, body.isEmpty() ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
		}
	}

	private String codeBody(String code) { return "grant_type=authorization_code&code=" + encode(code) + "&redirect_uri=" + encode(REDIRECT) + "&code_verifier=" + VERIFIER; }
	private String refreshBody(String token) { return "grant_type=refresh_token&refresh_token=" + encode(token); }
	private String basic() { return basic(this.clientId.toString(), this.secret); }
	private static String basic(String id, String secret) { return "Basic " + Base64.getEncoder().encodeToString((encode(id) + ":" + encode(secret)).getBytes(StandardCharsets.UTF_8)); }
	private IdentityAccessTokenVerifier verifier() { return new IdentityAccessTokenVerifier(this.accessTokens, "https://iam.example"); }

	private static JsonNode success(HttpResponse<String> response) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty();
		var json = new JsonMapper().readTree(response.body()); assertThat(json.path("token_type").asText()).isEqualToIgnoringCase("Bearer"); return json;
	}

	private static void error(HttpResponse<String> response, int status, String code) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(status); assertSecurityHeaders(response);
		assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty();
		assertThat(new JsonMapper().readTree(response.body()).properties()).containsExactly(Map.entry("error", new JsonMapper().getNodeFactory().stringNode(code)));
	}

	private List<List<String>> protocolSnapshot() {
		return List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_binding", "iam_authorization_binding_role", "iam_authorization_token_index", "iam_refresh_family", "iam_refresh_history").stream()
				.map(table -> this.jdbc.sql("SELECT row_to_json(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}
	private List<List<String>> sessionSnapshot() {
		return List.of("iam_browser_session", "iam_browser_session_attributes").stream()
				.map(table -> this.jdbc.sql("SELECT row_to_json(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}
	private void assertSingleRequestRejection() {
		assertThat(this.jdbc.sql("SELECT action FROM iam_security_audit WHERE action IN ('tokens_issued','token_request_rejected','tokens_refreshed','refresh_token_replayed','authorization_code_replayed')").query(String.class).list()).containsExactly("token_request_rejected");
	}
	private void assertNoSecretsInAudit(String... additional) {
		String stored = this.jdbc.sql("SELECT row_to_json(r)::text FROM iam_security_audit r").query(String.class).list().toString();
		assertThat(stored).doesNotContain(this.secret, VERIFIER, this.sessionId, "private-query", "private protocol test fault");
		assertThat(stored).doesNotContain(additional);
	}

}
