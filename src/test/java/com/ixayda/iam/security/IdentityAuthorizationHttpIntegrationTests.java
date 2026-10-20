package com.ixayda.iam.security;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityClientConfiguration;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static com.ixayda.iam.security.BrowserHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"iam.protocol.issuer=https://iam.example", "iam.protocol.identity-frontend-uri=https://iam.example/identity/authorize",
		"iam.browser.requests-per-second=1000", "springdoc.api-docs.enabled=true" })
class IdentityAuthorizationHttpIntegrationTests extends IdentityProtocolTestSupport {

	private static final JsonMapper JSON = new JsonMapper();
	private static final String AUTHORIZATION = "/oauth2/authorize";
	private static final String INTERACTIONS = "/api/authorization-interactions/";
	@LocalServerPort private int port;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry properties) {
		properties.add("server.ssl.enabled", () -> true); properties.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		properties.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@BeforeEach
	void cleanInteractions() { this.jdbc.sql("TRUNCATE iam_authorization_interaction").update(); }

	@AfterEach
	void removeAuthorizationFaults() {
		this.jdbc.sql("ALTER TABLE iam_authorization_interaction ENABLE TRIGGER USER").update();
		for (String table : List.of("iam_authorization_interaction", "iam_security_audit", "iam_browser_session")) { this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON " + table).update(); }
		this.jdbc.sql("TRUNCATE iam_authorization_interaction").update();
	}

	@Test
	void anAnonymousBrowserCanLoginAndResumeTheBoundRequestThenExchangeAndUseItsTokens() throws Exception {
		var start = start(Map.of(), null); var first = browserState(start.cookie());
		var view = success(get(INTERACTIONS + start.handle(), first.cookie()));
		assertThat(view.path("loginRequired").asBoolean()).isTrue(); assertThat(view.path("subject").isNull()).isTrue();
		assertThat(view.path("clientName").asText()).isEqualTo("Orders"); assertNoGrants();
		var authenticated = login(first);
		assertThat(authenticated.cookie()).isNotEqualTo(first.cookie());
		var afterLogin = success(get(INTERACTIONS + start.handle(), authenticated.cookie()));
		assertThat(afterLogin.path("loginRequired").asBoolean()).isFalse(); assertThat(afterLogin.path("subject").asText()).isEqualTo(this.userId.toString());
		var completed = success(complete(start.handle(), authenticated, "{\"decision\":\"continue\"}"));
		var callback = query(URI.create(completed.path("redirectUri").asText()));
		assertThat(callback.get("state")).isEqualTo("state-http-original"); assertThat(callback.get("code")).isNotBlank();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero();
		var tokens = token(callback.get("code"), this.clientId.toString(), this.secret, REDIRECT);
		assertThat(verified(tokens.path("access_token").asText(), "at+jwt").getSubject()).isEqualTo(this.userId.toString());
		assertThat(verified(tokens.path("id_token").asText(), "JWT").getStringClaim("nonce")).isEqualTo(NONCE);
		var info = send("/userinfo", "GET", null, null, null, Map.of("Authorization", "Bearer " + tokens.path("access_token").asText()));
		assertThat(success(info).path("sub").asText()).isEqualTo(this.userId.toString());
		assertNoSecretsInAudits(start.handle(), callback.get("code"), tokens.path("access_token").asText(), tokens.path("refresh_token").asText());
	}

	@Test
	void aSingleBrowserSessionSignsIntoTwoIndependentApplicationsWithoutAnotherPassword() throws Exception {
		String browser = seededCookie();
		var orders = get(authorize(Map.of()), browser); assertThat(orders.statusCode()).isEqualTo(302);
		var orderCallback = URI.create(orders.headers().firstValue("Location").orElseThrow()); assertThat(orderCallback.getHost()).isEqualTo("orders.example");
		var resource = this.resources.create("urn:example:billing", "Billing", AUDIT);
		var second = this.clients.create(new IdentityClientConfiguration("Billing", resource.id(), List.of("https://billing.example/callback"), Set.of("openid", "profile"), Set.of()), AUDIT);
		var billing = get(authorize(Map.of("client_id", second.client().id().toString(), "redirect_uri", "https://billing.example/callback", "scope", "openid profile")), browser);
		assertThat(billing.statusCode()).isEqualTo(302); var billingCallback = URI.create(billing.headers().firstValue("Location").orElseThrow());
		assertThat(billingCallback.getHost()).isEqualTo("billing.example");
		var orderToken = token(query(orderCallback).get("code"), this.clientId.toString(), this.secret, REDIRECT);
		var billingToken = token(query(billingCallback).get("code"), second.client().id().toString(), second.secret(), "https://billing.example/callback");
		assertThat(verified(orderToken.path("access_token").asText(), "at+jwt").getAudience()).containsExactly("urn:example:orders");
		assertThat(verified(billingToken.path("access_token").asText(), "at+jwt").getAudience()).containsExactly("urn:example:billing");
		assertThat(this.jdbc.sql("SELECT session_id FROM iam_browser_session WHERE principal_name=:user").param("user", this.userId.toString()).query(String.class).list()).containsExactly(this.sessionId);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero();
		assertThat(orders.headers().allValues("Set-Cookie")).isEmpty(); assertThat(billing.headers().allValues("Set-Cookie")).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "direct", "continue", "cancel" })
	void registeredCallbackQueriesAndReservedStateCharactersSurviveEveryRedirectPath(String outcome) throws Exception {
		String callback = "https://reports.example/callback?tenant=a%2Bb&source=iam";
		String state = "opaque-%2F+&=/#?:[]@!$'()*;,";
		var client = this.clients.create(new IdentityClientConfiguration("Reports", this.resourceId, List.of(callback), Set.of("openid", "profile", "offline_access"), Set.of()), AUDIT);
		var parameters = new HashMap<>(Map.of("client_id", client.client().id().toString(), "redirect_uri", callback, "state", state));
		URI redirected;
		if (outcome.equals("direct")) {
			var response = get(authorize(parameters), seededCookie()); assertThat(response.statusCode()).isEqualTo(302);
			redirected = URI.create(response.headers().firstValue("Location").orElseThrow());
		}
		else {
			parameters.put("prompt", "consent"); var started = start(parameters, seededCookie());
			redirected = URI.create(success(complete(started.handle(), browserState(started.cookie()), JSON.writeValueAsString(Map.of("decision", outcome)))).path("redirectUri").asText());
		}
		assertThat(redirected.toString()).startsWith(callback + "&");
		var values = query(redirected); assertThat(values).containsEntry("state", state).containsEntry("tenant", "a+b").containsEntry("source", "iam");
		if (outcome.equals("cancel")) { assertThat(values).containsEntry("error", "access_denied").doesNotContainKey("code"); assertNoGrants(); }
		else { assertThat(token(values.get("code"), client.client().id().toString(), client.secret(), callback).path("id_token").asText()).isNotBlank(); }
	}

	@Test
	void forwardingHeadersCannotChangeTheConfiguredAuthorizationIdentity() throws Exception {
		var response = send(authorize(Map.of()), "GET", null, seededCookie(), null,
				Map.of("Forwarded", "proto=https;host=attacker.example", "X-Forwarded-Host", "attacker.example", "X-Forwarded-Proto", "https"));
		assertThat(response.statusCode()).isEqualTo(302);
		var callback = URI.create(response.headers().firstValue("Location").orElseThrow());
		assertThat(callback.getHost()).isEqualTo("orders.example");
		var tokens = token(query(callback).get("code"), this.clientId.toString(), this.secret, REDIRECT);
		assertThat(verified(tokens.path("id_token").asText(), "JWT").getIssuer()).isEqualTo("https://iam.example");
	}

	@Test
	void interactionDisplayDoesNotExposeOriginalProtocolParametersOrSecrets() throws Exception {
		var started = start(Map.of("prompt", "consent"), seededCookie());
		var response = success(get(INTERACTIONS + started.handle(), started.cookie()));
		assertThat(response.propertyNames()).containsExactlyInAnyOrder("clientId", "clientName", "scopes", "expiresAt", "subject", "loginRequired", "selectionRequired", "consentRequired");
		assertThat(response.toString()).doesNotContain(started.handle(), NONCE, CHALLENGE, VERIFIER, this.secret, REDIRECT, "state-http-original");
	}

	@ParameterizedTest
	@ValueSource(strings = {"login", "max-age", "login consent select_account"})
	void forcedAuthenticationCannotBeSatisfiedByConfirmingTheExistingLogin(String prompt) throws Exception {
		var start = start(prompt.equals("max-age") ? Map.of("max_age", "0") : Map.of("prompt", prompt), seededCookie());
		var browser = browserState(start.cookie());
		assertThat(success(get(INTERACTIONS + start.handle(), browser.cookie())).path("loginRequired").asBoolean()).isTrue();
		error(complete(start.handle(), browser, "{\"decision\":\"continue\"}"), 401, "login_required"); assertNoGrants();
		var fresh = login(browser);
		assertThat(success(get(INTERACTIONS + start.handle(), fresh.cookie())).path("loginRequired").asBoolean()).isFalse();
		assertThat(success(complete(start.handle(), fresh, "{\"decision\":\"continue\"}")).path("redirectUri").asText()).contains("code=");
	}

	@ParameterizedTest
	@ValueSource(strings = {"consent", "select_account", "consent select_account"})
	void explicitSelectionAndConfirmationCanUseTheCurrentOwnedLogin(String prompt) throws Exception {
		var start = start(Map.of("prompt", prompt), seededCookie()); var browser = browserState(start.cookie());
		var view = success(get(INTERACTIONS + start.handle(), browser.cookie()));
		assertThat(view.path("loginRequired").asBoolean()).isFalse(); assertThat(view.path("selectionRequired").asBoolean()).isEqualTo(prompt.contains("select_account"));
		assertThat(view.path("consentRequired").asBoolean()).isEqualTo(prompt.contains("consent"));
		assertThat(success(complete(start.handle(), browser, "{\"decision\":\"continue\"}")).path("redirectUri").asText()).contains("code=");
	}

	@Test
	void promptNoneReturnsAClientErrorWithoutCreatingAnAnonymousSessionOrInteraction() throws Exception {
		long before = this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single();
		var response = get(authorize(Map.of("prompt", "none")), null); assertThat(response.statusCode()).isEqualTo(302);
		assertThat(query(URI.create(response.headers().firstValue("Location").orElseThrow()))).containsEntry("error", "login_required").containsEntry("state", "state-http-original");
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isEqualTo(before);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero(); assertNoGrants();
	}

	@Test
	void anAnonymousBrowserCanCancelOnceWithItsCsrfProofWithoutAssertingAUserIdentity() throws Exception {
		var start = start(Map.of(), null); var browser = browserState(start.cookie());
		var response = success(complete(start.handle(), browser, "{\"decision\":\"cancel\"}"));
		assertThat(query(URI.create(response.path("redirectUri").asText()))).containsExactlyInAnyOrderEntriesOf(Map.of("error", "access_denied", "state", "state-http-original"));
		assertNoGrants();
		assertThat(this.jdbc.sql("SELECT actor,target_user_id FROM iam_security_audit WHERE source='protocol:authorize:cancel'").query().singleRow()).containsEntry("actor", "anonymous").containsEntry("target_user_id", null);
		error(complete(start.handle(), browser, "{\"decision\":\"cancel\"}"), 400, "invalid_request");
	}

	@Test
	void anotherBrowserAndABearerCannotReadOrCompleteAnOwnedInteraction() throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var other = browserState(null);
		error(get(INTERACTIONS + start.handle(), other.cookie()), 400, "invalid_request");
		error(complete(start.handle(), other, "{\"decision\":\"continue\"}"), 400, "invalid_request");
		error(send(INTERACTIONS + start.handle(), "GET", null, start.cookie(), null, Map.of("Authorization", "Bearer private-untrusted")), 400, "invalid_request");
		assertNoGrants();
	}

	@ParameterizedTest
	@ValueSource(strings = {"redirect", "client", "response-type", "missing-state", "duplicate", "duplicate-unknown", "basic", "dpop", "body"})
	void invalidAuthorizationTransportAndUnregisteredDestinationsProduceOnlyLocalErrors(String invalid) throws Exception {
		String path = authorize(Map.of()); String body = null; Map<String, String> headers = Map.of();
		switch (invalid) {
			case "redirect" -> path = authorize(Map.of("redirect_uri", "https://attacker.example/callback"));
			case "client" -> path = authorize(Map.of("client_id", java.util.UUID.randomUUID().toString()));
			case "response-type" -> path = authorize(Map.of("response_type", "token"));
			case "missing-state" -> path = authorize(Map.of("state", ""));
			case "duplicate" -> path += "&scope=openid";
			case "duplicate-unknown" -> path += "&unknown=&unknown=";
			case "basic" -> headers = Map.of("Authorization", "Basic private-untrusted");
			case "dpop" -> headers = Map.of("DPoP", "private-untrusted");
			default -> body = "private-body";
		}
		var response = send(path, "GET", null, null, body, headers);
		// A well-formed registered callback can receive a validation error only after the provider checked it.
		if (invalid.equals("missing-state")) {
			assertThat(response.statusCode()).isEqualTo(302); assertThat(query(URI.create(response.headers().firstValue("Location").orElseThrow()))).containsEntry("error", "invalid_request").doesNotContainKey("state");
		}
		else { error(response, 400, "invalid_request"); }
		assertNoGrants(); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero();
		assertNoSecretsInAudits("private-untrusted", "private-body", "attacker.example");
	}

	@ParameterizedTest
	@ValueSource(strings = {"POST", "PUT", "DELETE", "OPTIONS"})
	void authorizationAcceptsOnlyGet(String method) throws Exception {
		var response = send(authorize(Map.of()), method, null, seededCookie(), null, Map.of());
		error(response, 405, "invalid_request"); assertThat(response.headers().firstValue("Allow")).contains("GET"); assertNoGrants();
	}

	@ParameterizedTest
	@ValueSource(strings = {"missing-csrf", "wrong-csrf", "query", "form", "charset", "get"})
	void completionRequiresSameSessionCsrfAndAnUnambiguousJsonPost(String invalid) throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie());
		String path = INTERACTIONS + start.handle() + "/complete", method = "POST", type = "application/json";
		Map<String, String> headers = Map.of("X-CSRF-TOKEN", browser.csrf()); int status = 400;
		switch (invalid) {
			case "missing-csrf" -> { headers = Map.of(); status = 403; }
			case "wrong-csrf" -> { headers = Map.of("X-CSRF-TOKEN", "private-wrong-csrf"); status = 403; }
			case "query" -> path += "?decision=continue";
			case "form" -> { type = "application/x-www-form-urlencoded"; status = 415; }
			case "charset" -> { type = "application/json;charset=UTF-16"; status = 415; }
			default -> { method = "GET"; status = 405; }
		}
		error(send(path, method, type, browser.cookie(), "{\"decision\":\"continue\"}", headers), status, "invalid_request");
		assertNoGrants(); assertThat(get(INTERACTIONS + start.handle(), browser.cookie()).statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = {"{}", "null", "[]", "{\"decision\":true}", "{\"decision\":\"CONTINUE\"}", "{\"decision\":\"continue\",\"decision\":\"cancel\"}", "{\"decision\":\"continue\",\"scope\":\"email\"}", "{\"decision\":\"continue\"}{}"})
	void malformedOrExpandedDecisionsCannotChangeOrConsumeTheOriginalRequest(String body) throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie());
		error(complete(start.handle(), browser, body), 400, "invalid_request"); assertNoGrants();
		assertThat(get(INTERACTIONS + start.handle(), browser.cookie()).statusCode()).isEqualTo(200);
	}

	@Test
	void aChunkedOversizedDecisionIsRejectedWithoutConsumingTheInteraction() throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie());
		byte[] oversized = ("{\"decision\":\"continue\"}" + " ".repeat(9000)).getBytes(StandardCharsets.UTF_8);
		try (var client = client()) {
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + INTERACTIONS + start.handle() + "/complete"))
					.header("Cookie", browser.cookie()).header("X-CSRF-TOKEN", browser.csrf()).header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(oversized))).build();
			error(client.send(request, HttpResponse.BodyHandlers.ofString()), 413, "invalid_request");
		}
		assertNoGrants(); assertThat(get(INTERACTIONS + start.handle(), browser.cookie()).statusCode()).isEqualTo(200);
	}

	@ParameterizedTest
	@ValueSource(strings = { "utf16", "malformed-utf8" })
	void invalidJsonEncodingsCannotBypassTheStrictUtf8Contract(String encoding) throws Exception {
		var started = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(started.cookie());
		byte[] bytes = encoding.equals("utf16") ? "{\"decision\":\"continue\"}".getBytes(StandardCharsets.UTF_16)
				: new byte[] {'{', '"', (byte) 0xc3, (byte) 0x28, '"', ':', '1', '}'};
		try (var client = client()) {
			var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + INTERACTIONS + started.handle() + "/complete"))
					.header("Cookie", browser.cookie()).header("X-CSRF-TOKEN", browser.csrf()).header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofByteArray(bytes)).build();
			error(client.send(request, HttpResponse.BodyHandlers.ofString()), 400, "invalid_request");
		}
		assertNoGrants(); assertThat(get(INTERACTIONS + started.handle(), browser.cookie()).statusCode()).isEqualTo(200);
	}

	@Test
	void concurrentFirstInteractionsKeepOneOwnerAcrossIndependentJdbcSessionSnapshots() throws Exception {
		var begin = new CountDownLatch(1); String browser = seededCookie();
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> { awaitLatch(begin); return start(Map.of("prompt", "consent"), browser); });
			var second = executor.submit(() -> { awaitLatch(begin); return start(Map.of("prompt", "select_account"), browser); }); begin.countDown();
			var one = first.get(15, TimeUnit.SECONDS); var two = second.get(15, TimeUnit.SECONDS);
			assertThat(one.handle()).isNotEqualTo(two.handle()); assertThat(get(INTERACTIONS + one.handle(), browser).statusCode()).isEqualTo(200);
			assertThat(get(INTERACTIONS + two.handle(), browser).statusCode()).isEqualTo(200);
		}
		assertThat(this.jdbc.sql("SELECT count(DISTINCT owner_digest) FROM iam_authorization_interaction").query(Long.class).single()).isEqualTo(1); assertNoGrants();
	}

	@Test
	void concurrentHttpConfirmationsPublishOnlyOneCommittedCode() throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie()); var begin = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> { awaitLatch(begin); return complete(start.handle(), browser, "{\"decision\":\"continue\"}"); });
			var second = executor.submit(() -> { awaitLatch(begin); return complete(start.handle(), browser, "{\"decision\":\"continue\"}"); }); begin.countDown();
			var responses = List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
			assertThat(responses).extracting(HttpResponse::statusCode).containsExactlyInAnyOrder(200, 400);
			error(responses.stream().filter(response -> response.statusCode() == 400).findFirst().orElseThrow(), 400, "invalid_request");
			var redirect = URI.create(success(responses.stream().filter(response -> response.statusCode() == 200).findFirst().orElseThrow()).path("redirectUri").asText());
			assertThat(token(query(redirect).get("code"), this.clientId.toString(), this.secret, REDIRECT).path("access_token").asText()).isNotBlank();
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM oauth2_authorization").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void cancellationAndConfirmationCannotBothCompleteOneInteraction() throws Exception {
		var started = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(started.cookie()); var begin = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> { awaitLatch(begin); return complete(started.handle(), browser, "{\"decision\":\"continue\"}"); });
			var second = executor.submit(() -> { awaitLatch(begin); return complete(started.handle(), browser, "{\"decision\":\"cancel\"}"); }); begin.countDown();
			var responses = List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
			assertThat(responses).extracting(HttpResponse::statusCode).containsExactlyInAnyOrder(200, 400);
			var redirect = query(URI.create(success(responses.stream().filter(response -> response.statusCode() == 200).findFirst().orElseThrow()).path("redirectUri").asText()));
			if (redirect.containsKey("error")) { assertThat(redirect).containsEntry("error", "access_denied"); assertNoGrants(); }
			else { assertThat(token(redirect.get("code"), this.clientId.toString(), this.secret, REDIRECT).path("access_token").asText()).isNotBlank(); }
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = {"code-audit", "cancel-audit", "commit"})
	void codeAuditCancellationAuditAndCommitFaultsNeverPublishCompletion(String failure) throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie());
		switch (failure) {
			case "code-audit" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "cancel-audit" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.source='protocol:authorize:cancel' THEN RETURN NULL; END IF; RETURN NEW;", false);
			default -> fault("iam_authorization_interaction", "AFTER DELETE", "RAISE EXCEPTION 'isolated HTTP commit failure';", true);
		}
		error(complete(start.handle(), browser, failure.equals("cancel-audit") ? "{\"decision\":\"cancel\"}" : "{\"decision\":\"continue\"}"), 503, "server_error");
		assertNoGrants(); assertThat(get(INTERACTIONS + start.handle(), browser.cookie()).statusCode()).isEqualTo(200);
		assertNoSecretsInAudits("isolated HTTP", start.handle());
	}

	@ParameterizedTest
	@ValueSource(strings = {"interaction", "browser"})
	void dependentStorageOutagesFailClosedWithSafeProtocolErrors(String storage) throws Exception {
		var start = start(Map.of("prompt", "consent"), seededCookie()); var browser = browserState(start.cookie());
		String table = storage.equals("interaction") ? "iam_authorization_interaction" : "iam_browser_session";
		this.jdbc.sql("ALTER TABLE " + table + " RENAME TO unavailable_authorization_store").update();
		try { error(get(INTERACTIONS + start.handle(), browser.cookie()), 503, "server_error"); }
		finally { this.jdbc.sql("ALTER TABLE unavailable_authorization_store RENAME TO " + table).update(); }
		assertNoGrants(); assertThat(get(INTERACTIONS + start.handle(), browser.cookie()).statusCode()).isEqualTo(200);
	}

	@Test
	void actualSwaggerIncludesOnlyTheEnabledAuthorizationAndFrontendOperations() throws Exception {
		var document = success(get("/v3/api-docs", seededCookie())); var spec = document.path("paths");
		var authorize = spec.path(AUTHORIZATION).path("get"); assertThat(authorize.path("operationId").asText()).isEqualTo("authorizeApplication");
		assertThat(spec.path(AUTHORIZATION).propertyNames()).containsExactly("get"); assertThat(authorize.path("security").isArray()).isTrue(); assertThat(authorize.path("security").size()).isZero();
		assertThat(authorize.path("parameters").toString()).contains("code_challenge", "S256", "max_age", "prompt");
		var view = spec.path(INTERACTIONS + "{handle}").path("get"); var complete = spec.path(INTERACTIONS + "{handle}/complete").path("post");
		assertThat(view.path("operationId").asText()).isEqualTo("getAuthorizationInteraction"); assertThat(view.path("security").size()).isZero();
		assertThat(complete.path("operationId").asText()).isEqualTo("completeAuthorizationInteraction"); assertThat(complete.path("security").size()).isZero();
		assertThat(complete.path("parameters").toString()).contains("X-CSRF-TOKEN");
		var decision = document.path("components").path("schemas").path("IdentityAuthorizationDecisionRequest");
		assertThat(decision.path("required").valueStream().map(JsonNode::asText).toList()).containsExactly("decision");
		assertThat(decision.path("properties").path("decision").path("enum").valueStream().map(JsonNode::asText).toList()).containsExactly("continue", "cancel");
		assertThat(decision.path("additionalProperties").isBoolean()).isTrue();
		assertThat(decision.path("additionalProperties").asBoolean()).isFalse();
		for (var operation : List.of(view, complete)) {
			for (String status : List.of("400", "401", "403", "405", "413", "415", "429", "503")) {
				assertThat(operation.path("responses").path(status).path("content").path("application/json").path("schema").path("$ref").asText())
						.isEqualTo("#/components/schemas/IdentityProtocolError");
			}
		}
		assertThat(spec.path("/.well-known/openid-configuration").path("get").path("operationId").asText()).isEqualTo("getOpenIdConfiguration");
	}

	private Started start(Map<String, String> extras, String browser) throws Exception {
		var response = get(authorize(extras), browser); assertThat(response.statusCode()).as(response.body()).isEqualTo(302); assertSecurityHeaders(response);
		var location = URI.create(response.headers().firstValue("Location").orElseThrow());
		assertThat(location.getScheme()).isEqualTo("https"); assertThat(location.getHost()).isEqualTo("iam.example"); assertThat(location.getPath()).isEqualTo("/identity/authorize");
		var query = query(location); assertThat(query.keySet()).containsExactly("interaction"); assertThat(query.get("interaction")).matches("[A-Za-z0-9_-]{43}");
		String cookie = response.headers().allValues("Set-Cookie").isEmpty() ? browser : cookie(response);
		return new Started(query.get("interaction"), cookie);
	}
	private BrowserState browserState(String cookie) throws Exception {
		var response = get("/api/csrf", cookie); return new BrowserState(response.headers().allValues("Set-Cookie").isEmpty() ? cookie : cookie(response), csrf(response));
	}
	private BrowserState login(BrowserState browser) throws Exception {
		var response = send("/login", "POST", "application/json", browser.cookie(), JSON.writeValueAsString(Map.of("username", "alice", "password", PASSWORD)), Map.of("X-CSRF-TOKEN", browser.csrf()));
		assertThat(response.statusCode()).as(response.body()).isEqualTo(204); return browserState(cookie(response));
	}
	private HttpResponse<String> complete(String handle, BrowserState browser, String body) throws Exception {
		return send(INTERACTIONS + handle + "/complete", "POST", "application/json", browser.cookie(), body, Map.of("X-CSRF-TOKEN", browser.csrf()));
	}
	private HttpResponse<String> get(String path, String cookie) throws Exception { return send(path, "GET", null, cookie, null, Map.of()); }
	private HttpResponse<String> send(String path, String method, String contentType, String cookie, String body, Map<String, String> headers) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (contentType != null) { request.header("Content-Type", contentType); } if (cookie != null) { request.header("Cookie", cookie); } headers.forEach(request::header);
		try (var client = client()) { return client.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private JsonNode token(String code, String clientId, String secret, String redirect) throws Exception {
		String basic = "Basic " + Base64.getEncoder().encodeToString((encode(clientId) + ":" + encode(secret)).getBytes(StandardCharsets.US_ASCII));
		return success(send("/oauth2/token", "POST", "application/x-www-form-urlencoded", null,
				"grant_type=authorization_code&code=" + encode(code) + "&redirect_uri=" + encode(redirect) + "&code_verifier=" + VERIFIER, Map.of("Authorization", basic)));
	}
	private String authorize(Map<String, String> extras) {
		var parameters = new LinkedHashMap<String, String>(); parameters.put("response_type", "code"); parameters.put("client_id", this.clientId.toString()); parameters.put("redirect_uri", REDIRECT);
		parameters.put("scope", "openid profile offline_access"); parameters.put("state", "state-http-original"); parameters.put("code_challenge", CHALLENGE); parameters.put("code_challenge_method", "S256"); parameters.put("nonce", NONCE); parameters.putAll(extras);
		return AUTHORIZATION + "?" + parameters.entrySet().stream().map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue())).collect(java.util.stream.Collectors.joining("&"));
	}
	private String seededCookie() { return "__Host-IAMSESSION=" + this.sessionId; }
	private static Map<String, String> query(URI uri) {
		var values = new HashMap<String, String>(); for (String entry : uri.getRawQuery().split("&")) { var parts = entry.split("=", 2); values.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1], StandardCharsets.UTF_8)); } return values;
	}
	private static JsonNode success(HttpResponse<String> response) { assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response); return JSON.readTree(response.body()); }
	private static void error(HttpResponse<String> response, int status, String code) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(status); assertSecurityHeaders(response); assertThat(response.headers().allValues("Location")).isEmpty();
		var body = JSON.readTree(response.body()); assertThat(body.propertyNames()).containsExactly("error"); assertThat(body.path("error").asText()).isEqualTo(code);
	}
	private void assertNoGrants() { assertThat(this.jdbc.sql("SELECT count(*) FROM oauth2_authorization").query(Long.class).single()).isZero(); }
	private void assertNoSecretsInAudits(String... values) { var rows = this.jdbc.sql("SELECT to_jsonb(a)::text FROM iam_security_audit a").query(String.class).list().toString(); assertThat(rows).doesNotContain(values).doesNotContain(this.secret, PASSWORD, VERIFIER, NONCE, "state-http-original"); }
	private record BrowserState(String cookie, String csrf) { }
	private record Started(String handle, String cookie) { }

}
