package com.ixayda.iam.security;

import java.io.ByteArrayInputStream;
import java.net.URI;
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
import com.ixayda.iam.service.IdentityAccessTokens;
import com.ixayda.iam.service.IdentityResourceCredentials;
import com.nimbusds.jwt.SignedJWT;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.protocol.identity-frontend-uri=https://iam.example/identity/authorize",
		"iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityIntrospectionHttpIntegrationTests extends IdentityProtocolTestSupport {

	private static final String ENDPOINT = "/oauth2/introspect";
	private static final JsonMapper JSON = new JsonMapper();
	@LocalServerPort private int port;
	@Autowired private IdentityResourceCredentials credentials;
	@Autowired private IdentityAccessTokens access;
	private String resourceSecret;
	private IdentityIntrospectionProvider introspection;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry registry) {
		registry.add("server.ssl.enabled", () -> true); registry.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		registry.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@BeforeEach
	void resourceCredential() {
		this.resourceSecret = this.credentials.rotateSecret(this.resourceId, 0, AUDIT).secret();
		this.introspection = new IdentityIntrospectionProvider(new IdentityAccessTokenVerifier(this.access, "https://iam.example"), this.credentials, this.audits, this.transactions, "https://iam.example");
	}

	@Test
	void resourceReceivesOnlyItsCurrentApplicationProjectionWithoutMutatingGrantOrBrowserState() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access")); var issued = exchange(request(code, authenticatedClient(code)));
		String bearer = issued.getAccessToken().getTokenValue(); var claims = SignedJWT.parse(bearer).getJWTClaimsSet();
		var grants = grantSnapshot(); var sessions = sessionSnapshot(); long before = auditCount();
		var response = inspect(bearer); var result = success(response);
		assertThat(result.propertyNames()).containsExactlyInAnyOrder("active", "token_type", "iss", "sub", "client_id", "aud", "scope", "iat", "nbf", "exp", "roles");
		assertThat(result.path("active").asBoolean()).isTrue(); assertThat(result.path("token_type").asText()).isEqualTo("Bearer");
		assertThat(result.path("iss").asText()).isEqualTo("https://iam.example");
		assertThat(result.path("sub").asText()).isEqualTo(this.userId.toString()); assertThat(result.path("client_id").asText()).isEqualTo(this.clientId.toString());
		assertThat(result.path("aud").get(0).asText()).isEqualTo("urn:example:orders");
		assertThat(result.path("scope").asText()).isEqualTo("offline_access openid profile");
		assertThat(result.path("roles").get(0).asText()).isEqualTo("reader");
		assertThat(result.path("exp").asLong()).isEqualTo(claims.getExpirationTime().toInstant().getEpochSecond());
		assertThat(result.path("iat").asLong()).isEqualTo(claims.getIssueTime().toInstant().getEpochSecond());
		assertThat(grantSnapshot()).isEqualTo(grants); assertThat(sessionSnapshot()).isEqualTo(sessions); assertThat(auditCount()).isEqualTo(before);
		assertThat(response.body()).doesNotContain(bearer, this.secret, this.resourceSecret, PASSWORD, "username", "preferred_username", "ROLE_IAM_ADMIN", "authorization_id");
		var authentication = this.introspection.authenticateResource(this.resourceId.toString(), this.resourceSecret);
		assertThat(authentication.getAuthorities()).isEmpty(); assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.toString()).isEqualTo("ResourceAuthentication[REDACTED]");
		assertThatIllegalArgumentException().isThrownBy(() -> authentication.setAuthenticated(true));
	}

	@Test
	void anotherResourceCannotDiscoverClaimsEvenWhenTheAudienceMatchesItsCallerSuppliedHint() throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		UUID other = this.resources.create("urn:other", "Other", AUDIT).id(); String proof = this.credentials.rotateSecret(other, 0, AUDIT).secret();
		inactive(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer), basic(other.toString(), proof), Map.of()));
		assertThat(this.jdbc.sql("SELECT actor FROM iam_security_audit WHERE action='introspection_rejected'").query(String.class).single()).isEqualTo("resource:" + other);
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer) + "&resource=" + this.resourceId,
				basic(other.toString(), proof), Map.of()), 400, "invalid_request");
		assertThat(success(inspect(bearer)).path("active").asBoolean()).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "id_token", "refresh_token", "code", "unknown", "malformed", "signature" })
	void unsupportedUnknownAndTamperedTokensHaveOnlyInactiveResponse(String type) throws Exception {
		String code = code(Set.of("openid", "offline_access")); var issued = exchange(request(code, authenticatedClient(code)));
		String bearer = issued.getAccessToken().getTokenValue();
		String raw = switch (type) {
			case "id_token" -> issued.getAdditionalParameters().get("id_token").toString(); case "refresh_token" -> issued.getRefreshToken().getTokenValue();
			case "code" -> code; case "unknown" -> "private-unknown-token"; case "malformed" -> "a.b.c";
			default -> {
				int index = bearer.lastIndexOf('.') + 1; String changed = bearer.substring(0, index) + (bearer.charAt(index) == 'A' ? 'B' : 'A') + bearer.substring(index + 1);
				var stored = stored(code); var token = issued.getAccessToken();
				this.authorizations.save(OAuth2Authorization.from(stored.authorization()).token(new org.springframework.security.oauth2.core.OAuth2AccessToken(token.getTokenType(), changed, token.getIssuedAt(), token.getExpiresAt(), token.getScopes()),
						metadata -> metadata.putAll(stored.authorization().getAccessToken().getMetadata())).build(), stored.version());
				yield changed;
			}
		};
		inactive(inspect(raw)); assertThat(auditCount()).isEqualTo(1); assertNoSecretsInAudit(raw, bearer, this.resourceSecret, this.secret);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-disabled", "credential", "client-secret", "client-disabled", "client-transferred", "resource", "role", "role-disabled", "assignment" })
	void currentGrantChangesOverrideAnUnexpiredSignature(String mutation) throws Exception {
		String code = code(Set.of("openid", "profile")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		mutate(mutation); inactive(inspect(bearer)); assertThat(auditCount()).isEqualTo(1);
	}

	@Test
	void hintsDoNotPermitOtherTokenTypesOrHideSupportedAccessTokens() throws Exception {
		String code = code(Set.of("openid")); var issued = exchange(request(code, authenticatedClient(code))); String bearer = issued.getAccessToken().getTokenValue();
		for (String hint : List.of("", "access_token", "refresh_token", "unknown")) {
			assertThat(success(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer) + "&token_type_hint=" + hint, proof(), Map.of())).path("active").asBoolean()).isTrue();
		}
	}

	@Test
	void applicationClientAndBrowserAuthenticationCannotActAsResourceCredentialsOrUseResourceIdentityAtTokenEndpoint() throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		for (String auth : List.of(basic(this.clientId.toString(), this.secret), basic(this.resourceId.toString(), this.secret), "Bearer " + bearer)) {
			error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer), auth, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)), 401, "invalid_client");
		}
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer), null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)), 401, "invalid_client");
		error(send("/oauth2/token", "POST", "application/x-www-form-urlencoded", "grant_type=refresh_token&refresh_token=private-refresh", proof(), Map.of()), 401, "invalid_client");
		var browser = UsernamePasswordAuthenticationToken.authenticated(this.userId, null, List.of());
		var rejected = new OAuth2TokenIntrospectionAuthenticationToken(bearer, browser, null, Map.of()); rejected.setDetails(new IdentityIntrospectionProvider.Evidence(UUID.randomUUID()));
		assertDenied(() -> this.introspection.authenticate(rejected), "invalid_client");
	}

	@ParameterizedTest
	@ValueSource(strings = { "rotate", "disable", "resource-disabled" })
	void authenticationSnapshotCannotOutliveResourceOrCredentialChangesEvenForMalformedTokens(String change) throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		var resource = this.introspection.authenticateResource(this.resourceId.toString(), this.resourceSecret);
		switch (change) {
			case "rotate" -> this.credentials.rotateSecret(this.resourceId, 1, AUDIT); case "disable" -> this.credentials.disable(this.resourceId, 1, AUDIT);
			default -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		}
		for (String raw : List.of(bearer, "malformed")) {
			var request = new OAuth2TokenIntrospectionAuthenticationToken(raw, resource, null, Map.of()); request.setDetails(new IdentityIntrospectionProvider.Evidence(UUID.randomUUID()));
			assertDenied(() -> this.introspection.authenticate(request), "invalid_client"); error(inspect(raw), 401, "invalid_client");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "valid", "malformed" })
	void aQueuedValidationRechecksTheRotatedCredentialAfterWaitingForResourceLock(String type) throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		var resource = this.introspection.authenticateResource(this.resourceId.toString(), this.resourceSecret);
		var request = new OAuth2TokenIntrospectionAuthenticationToken(type.equals("valid") ? bearer : "malformed", resource, null, Map.of());
		request.setDetails(new IdentityIntrospectionProvider.Evidence(UUID.randomUUID()));
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var rotation = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.credentials.rotateSecret(this.resourceId, 1, AUDIT); locked.countDown(); awaitLatch(release);
			}));
			assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
			var validation = executor.submit(() -> assertDenied(() -> this.introspection.authenticate(request), "invalid_client"));
			try { await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%iam_resource%'").query(Long.class).single() > 0); }
			finally { release.countDown(); }
			rotation.get(10, TimeUnit.SECONDS); validation.get(10, TimeUnit.SECONDS);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE" })
	void onlyPostIsAllowedAndMethodFailuresAreAudited(String method) throws Exception {
		var response = send(ENDPOINT, method, null, null, null, Map.of());
		assertThat(response.statusCode()).isEqualTo(405); assertThat(response.headers().firstValue("Allow")).contains("POST"); assertSecurityHeaders(response);
		if (!method.equals("HEAD")) { error(response, 405, "invalid_request"); }
		assertThat(auditCount()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "empty", "duplicate", "hint-duplicate", "query", "body-client", "body-secret", "resource", "audience", "dpop", "authorization-duplicate", "json", "charset", "oversized" })
	void alternateOrAmbiguousTransportIsRejectedAndAuditedWithoutReflectingInput(String type) throws Exception {
		String path = ENDPOINT; String form = "token=private-probe"; String contentType = "application/x-www-form-urlencoded"; var headers = Map.<String, String>of();
		switch (type) {
			case "missing" -> form=""; case "empty" -> form="token="; case "duplicate" -> form+="&token=another"; case "hint-duplicate" -> form+="&token_type_hint=&token_type_hint=";
			case "query" -> path+="?token=private-query"; case "body-client" -> form+="&client_id=" + this.resourceId; case "body-secret" -> form+="&client_secret=private-secret";
			case "resource" -> form+="&resource=" + this.resourceId; case "audience" -> form+="&audience=urn:example:orders";
			case "dpop" -> headers=Map.of("DPoP", "private-proof"); case "authorization-duplicate" -> headers=Map.of("Authorization", proof());
			case "json" -> contentType="application/json"; case "charset" -> contentType+="; charset=UTF-16"; default -> form+="x".repeat(8193);
		}
		var response = send(path, "POST", contentType, form, proof(), headers);
		error(response, type.equals("json") || type.equals("charset") ? 415 : type.equals("oversized") ? 413 : 400, "invalid_request");
		assertThat(auditCount()).isEqualTo(1); assertNoSecretsInAudit("private-probe", "private-query", "private-secret", "private-proof", this.resourceSecret);
	}

	@Test
	void introspectionDoesNotReadOrRefreshBrowserSessionsEvenWithAnIamCookie() throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		var before = sessionSnapshot();
		success(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer), proof(), Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)));
		assertThat(sessionSnapshot()).isEqualTo(before);
		this.jdbc.sql("ALTER TABLE iam_browser_session RENAME TO isolated_introspection_browser").update();
		try { assertThat(success(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(bearer), proof(), Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId))).path("active").asBoolean()).isTrue(); }
		finally { this.jdbc.sql("ALTER TABLE isolated_introspection_browser RENAME TO iam_browser_session").update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "Basic !!!", "Basic YWJj", "Basic Og==", "Basic YTpiOmM=", "Basic " })
	void malformedBasicCredentialsRequireResourceAuthenticationWithoutLeakingTheirContents(String authorization) throws Exception {
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=private-probe", authorization, Map.of()), 401, "invalid_client");
		assertThat(auditCount()).isEqualTo(1); assertNoSecretsInAudit("private-probe", this.resourceSecret);
	}

	@Test
	void oversizedChunkedFormsAreRejectedBeforeResourceAuthenticationAndAudited() throws Exception {
		byte[] body = ("token=" + "x".repeat(8193)).getBytes(StandardCharsets.US_ASCII);
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + ENDPOINT)).timeout(Duration.ofSeconds(20))
				.header("Content-Type", "application/x-www-form-urlencoded").header("Authorization", proof())
				.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(body))).build();
		try (var client = client()) { error(client.send(request, HttpResponse.BodyHandlers.ofString()), 400, "invalid_request"); }
		assertThat(auditCount()).isEqualTo(1);
	}

	@Test
	void swaggerDescribesResourceAuthenticationAndDistinctActiveAndInactiveResponses() throws Exception {
		var response = send("/v3/api-docs", "GET", null, null, null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
		assertThat(response.statusCode()).isEqualTo(200);
		var document = JSON.readTree(response.body()); var path = document.path("paths").path(ENDPOINT); var operation = path.path("post");
		assertThat(path.propertyNames()).containsExactly("post");
		assertThat(operation.path("operationId").asText()).isEqualTo("introspectResourceToken");
		assertThat(operation.path("security").size()).isEqualTo(1); assertThat(operation.path("security").get(0).propertyNames()).containsExactly("resourceValidator");
		assertThat(document.path("components").path("securitySchemes").path("resourceValidator").path("scheme").asText()).isEqualTo("basic");
		var request = operation.path("requestBody").path("content").path("application/x-www-form-urlencoded").path("schema");
		assertThat(request.path("properties").propertyNames()).containsExactlyInAnyOrder("token", "token_type_hint");
		assertThat(request.path("required").get(0).asText()).isEqualTo("token"); assertThat(request.path("additionalProperties").asBoolean()).isFalse();
		var choices = operation.path("responses").path("200").path("content").path("application/json").path("schema").path("oneOf");
		assertThat(choices.size()).isEqualTo(2); var active = choices.get(0); var inactive = choices.get(1);
		assertThat(active.path("properties").propertyNames()).containsExactlyInAnyOrder("active", "token_type", "iss", "sub", "client_id", "aud", "scope", "roles", "iat", "nbf", "exp");
		assertThat(active.path("properties").path("active").path("enum").get(0).asBoolean()).isTrue();
		assertThat(inactive.path("properties").propertyNames()).containsExactly("active");
		assertThat(inactive.path("properties").path("active").path("enum").get(0).asBoolean()).isFalse(); assertThat(inactive.path("additionalProperties").asBoolean()).isFalse();
		for (String status : List.of("400", "401", "405", "413", "415", "429", "503")) {
			assertThat(operation.path("responses").path(status).path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityProtocolError");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "iam_resource_credential", "oauth2_authorization", "iam_user" })
	void onlineDependencyFailureCannotProduceClaimsOrInactiveSuccess(String table) throws Exception {
		String code = code(Set.of("openid")); String bearer = exchange(request(code, authenticatedClient(code))).getAccessToken().getTokenValue();
		this.jdbc.sql("ALTER TABLE " + table + " RENAME TO isolated_introspection_dependency").update();
		try { error(inspect(bearer), 503, "server_error"); }
		finally { this.jdbc.sql("ALTER TABLE isolated_introspection_dependency RENAME TO " + table).update(); }
		assertThat(auditCount()).isEqualTo(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "suppressed", "altered", "unavailable", "deferred" })
	void failedMandatoryAuditPreventsInactiveSuccessAndUnauditedAuthenticationErrors(String failure) throws Exception {
		String body = switch (failure) {
			case "suppressed" -> "IF NEW.action='introspection_rejected' THEN RETURN NULL; END IF; RETURN NEW;";
			case "altered" -> "IF NEW.action='introspection_rejected' THEN NEW.source='altered'; END IF; RETURN NEW;";
			default -> "RAISE EXCEPTION 'private introspection audit fault';";
		};
		fault("iam_security_audit", failure.equals("deferred") ? "AFTER INSERT" : "BEFORE INSERT", body, failure.equals("deferred"));
		error(inspect("private-invalid-token"), 503, "server_error");
		error(send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=private-invalid-token", null, Map.of()), 503, "server_error");
		assertThat(auditCount()).isZero();
		this.jdbc.sql("DROP FUNCTION exchange_test_fault() CASCADE").update();
	}

	private HttpResponse<String> inspect(String token) throws Exception { return send(ENDPOINT, "POST", "application/x-www-form-urlencoded", "token=" + encode(token), proof(), Map.of()); }
	private String proof() { return basic(this.resourceId.toString(), this.resourceSecret); }
	private static String basic(String id, String secret) { return "Basic " + Base64.getEncoder().encodeToString((encode(id) + ":" + encode(secret)).getBytes(StandardCharsets.US_ASCII)); }
	private HttpResponse<String> send(String path, String method, String contentType, String body, String proof, Map<String, String> headers) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (contentType != null) { request.header("Content-Type", contentType); } if (proof != null) { request.header("Authorization", proof); } headers.forEach(request::header);
		try (var client = client()) { return client.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private static JsonNode success(HttpResponse<String> response) { assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); return JSON.readTree(response.body()); }
	private static void inactive(HttpResponse<String> response) { var value=success(response); assertThat(value.propertyNames()).containsExactly("active"); assertThat(value.path("active").asBoolean()).isFalse(); }
	private static void error(HttpResponse<String> response, int status, String code) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(status); assertSecurityHeaders(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(JSON.readTree(response.body()).path("error").asText()).isEqualTo(code); assertThat(response.headers().firstValue("Location")).isEmpty();
		if (status == 401) { assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow()).isEqualTo(response.uri().getPath().equals(ENDPOINT) ? "Basic realm=\"iam/introspection\"" : "Basic realm=\"iam/token\""); }
	}
	private long auditCount() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='introspection_rejected'").query(Long.class).single(); }
	private List<List<String>> grantSnapshot() { return List.of("oauth2_authorization", "iam_authorization_record", "iam_refresh_family", "iam_refresh_history").stream().map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList(); }
	private List<String> sessionSnapshot() { return this.jdbc.sql("SELECT to_jsonb(s)::text FROM iam_browser_session s ORDER BY primary_id").query(String.class).list(); }
	private void assertNoSecretsInAudit(String... secrets) { assertThat(this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list().toString()).doesNotContain(secrets); }
	private static OAuth2AuthenticationException assertDenied(Runnable call, String code) {
		var failure = catchThrowableOfType(OAuth2AuthenticationException.class, call::run); assertThat(failure).isNotNull(); assertThat(failure.getError().getErrorCode()).isEqualTo(code); assertThat(failure.getCause()).isNull(); return failure;
	}

}
