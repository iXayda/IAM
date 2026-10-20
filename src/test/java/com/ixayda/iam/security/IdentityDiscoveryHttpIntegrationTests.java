package com.ixayda.iam.security;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ixayda.iam.IdentityProtocolTestSupport;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

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
class IdentityDiscoveryHttpIntegrationTests extends IdentityProtocolTestSupport {

	private static final JsonMapper JSON = new JsonMapper();
	@LocalServerPort private int port;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry properties) {
		properties.add("server.ssl.enabled", () -> true); properties.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		properties.add("server.ssl.key-store-password", () -> "test-store-password");
	}

	@ParameterizedTest
	@ValueSource(strings = { "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" })
	void discoveryAdvertisesOnlyEnabledCapabilitiesFromTheFixedIssuer(String path) throws Exception {
		var response = send(path, "GET", null, null, Map.of("Forwarded", "proto=https;host=attacker.example", "X-Forwarded-Host", "attacker.example"));
		var metadata = success(response);
		assertThat(response.headers().allValues("Set-Cookie")).isEmpty(); assertThat(response.headers().firstValue("Location")).isEmpty();
		assertThat(metadata.path("issuer").asText()).isEqualTo("https://iam.example");
		assertThat(metadata.path("authorization_endpoint").asText()).isEqualTo("https://iam.example/oauth2/authorize");
		assertThat(metadata.path("token_endpoint").asText()).isEqualTo("https://iam.example/oauth2/token");
		assertThat(metadata.path("jwks_uri").asText()).isEqualTo("https://iam.example/oauth2/jwks");
		assertThat(values(metadata, "grant_types_supported")).containsExactly("authorization_code", "refresh_token");
		assertThat(values(metadata, "token_endpoint_auth_methods_supported")).containsExactly("client_secret_basic");
		assertThat(values(metadata, "response_types_supported")).containsExactly("code");
		assertThat(values(metadata, "response_modes_supported")).containsExactly("query");
		assertThat(values(metadata, "code_challenge_methods_supported")).containsExactly("S256");
		assertThat(values(metadata, "scopes_supported")).containsExactly("openid", "profile", "offline_access");
		assertThat(metadata.has("introspection_endpoint")).isFalse(); assertThat(metadata.has("revocation_endpoint")).isFalse();
		assertThat(metadata.has("end_session_endpoint")).isFalse(); assertThat(metadata.has("registration_endpoint")).isFalse();
		assertThat(metadata.has("device_authorization_endpoint")).isFalse(); assertThat(metadata.has("pushed_authorization_request_endpoint")).isFalse();
		assertThat(metadata.has("dpop_signing_alg_values_supported")).isFalse(); assertThat(metadata.has("tls_client_certificate_bound_access_tokens")).isFalse();
		if (path.contains("openid")) {
			assertThat(metadata.path("userinfo_endpoint").asText()).isEqualTo("https://iam.example/userinfo");
			assertThat(values(metadata, "subject_types_supported")).containsExactly("public");
			assertThat(values(metadata, "id_token_signing_alg_values_supported")).containsExactly("RS256");
			assertThat(values(metadata, "claims_supported")).contains("sub", "name", "preferred_username", "nonce", "auth_time").doesNotContain("amr", "email");
			for (String name : List.of("claims_parameter_supported", "request_parameter_supported", "request_uri_parameter_supported")) { assertThat(metadata.path(name).asBoolean()).isFalse(); }
		}
		else { assertThat(metadata.has("userinfo_endpoint")).isFalse(); assertThat(metadata.has("claims_supported")).isFalse(); }
		assertThat(response.body()).doesNotContain(this.secret, PASSWORD, VERIFIER, "attacker.example");
	}

	@ParameterizedTest
	@ValueSource(strings = { "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" })
	void publicMetadataDoesNotReadOrRefreshBrowserSessionsAndDoesNotActAsAHealthCheck(String path) throws Exception {
		long expiry = this.jdbc.sql("SELECT expiry_time FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).query(Long.class).single();
		success(send(path, "GET", null, null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)));
		assertThat(this.jdbc.sql("SELECT expiry_time FROM iam_browser_session WHERE session_id=:id").param("id", this.sessionId).query(Long.class).single()).isEqualTo(expiry);
		this.jdbc.sql("ALTER TABLE iam_browser_session RENAME TO unavailable_discovery_browser").update();
		try {
			var response = send(path, "GET", null, null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
			success(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		}
		finally { this.jdbc.sql("ALTER TABLE unavailable_discovery_browser RENAME TO iam_browser_session").update(); }
	}

	@Test
	void metadataConnectsTheRealAuthorizationKeyTokenAndUserInfoEndpoints() throws Exception {
		var metadata = success(send("/.well-known/openid-configuration", "GET", null, null, Map.of()));
		var jwks = success(send(URI.create(metadata.path("jwks_uri").asText()).getPath(), "GET", null, null, Map.of()));
		assertThat(jwks.path("keys").get(0).path("kid").asText()).isEqualTo(this.signing.id().toString());
		String authorization = URI.create(metadata.path("authorization_endpoint").asText()).getPath() + "?response_type=code&client_id=" + this.clientId
				+ "&redirect_uri=" + encode(REDIRECT) + "&scope=" + encode("openid profile offline_access") + "&state=discovery-state&nonce=" + NONCE
				+ "&code_challenge=" + CHALLENGE + "&code_challenge_method=S256";
		var authorized = send(authorization, "GET", null, null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId));
		assertThat(authorized.statusCode()).isEqualTo(302);
		var callback = query(URI.create(authorized.headers().firstValue("Location").orElseThrow())); assertThat(callback).containsEntry("state", "discovery-state");
		String basic = "Basic " + Base64.getEncoder().encodeToString((encode(this.clientId.toString()) + ":" + encode(this.secret)).getBytes(StandardCharsets.US_ASCII));
		var token = success(send(URI.create(metadata.path("token_endpoint").asText()).getPath(), "POST", "application/x-www-form-urlencoded",
				"grant_type=authorization_code&code=" + encode(callback.get("code")) + "&redirect_uri=" + encode(REDIRECT) + "&code_verifier=" + VERIFIER, Map.of("Authorization", basic)));
		assertThat(verified(token.path("id_token").asText(), "JWT").getIssuer()).isEqualTo(metadata.path("issuer").asText());
		var profile = success(send(URI.create(metadata.path("userinfo_endpoint").asText()).getPath(), "GET", null, null, Map.of("Authorization", "Bearer " + token.path("access_token").asText())));
		assertThat(profile.path("sub").asText()).isEqualTo(this.userId.toString()); assertThat(profile.path("preferred_username").asText()).isEqualTo("alice");
	}

	@ParameterizedTest
	@ValueSource(strings = { "POST", "PUT", "DELETE", "OPTIONS" })
	void metadataAcceptsOnlyGet(String method) throws Exception {
		for (String path : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
			var response = send(path, method, null, null, Map.of()); error(response, 405); assertThat(response.headers().firstValue("Allow")).contains("GET");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "query", "body", "oversized" })
	void metadataRejectsQueryStringsAndRequestBodies(String invalid) throws Exception {
		for (String path : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
			String body = invalid.equals("query") ? null : invalid.equals("oversized") ? "x".repeat(8193) : "private-request";
			error(send(path + (invalid.equals("query") ? "?issuer=https://attacker.example" : ""), "GET", null, body, Map.of()), invalid.equals("oversized") ? 413 : 400);
		}
	}

	@Test
	void swaggerPublishesBothMetadataReadsWithoutCookieAuthentication() throws Exception {
		var document = success(send("/v3/api-docs", "GET", null, null, Map.of("Cookie", "__Host-IAMSESSION=" + this.sessionId)));
		for (String path : List.of("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")) {
			var route = document.path("paths").path(path); assertThat(route.propertyNames()).containsExactly("get");
			assertThat(route.path("get").path("security").isArray()).isTrue(); assertThat(route.path("get").path("security").size()).isZero();
			assertThat(route.path("get").path("responses").path("400").path("content").path("application/json").path("schema").path("$ref").asText())
					.isEqualTo("#/components/schemas/IdentityProtocolError");
		}
	}

	private HttpResponse<String> send(String path, String method, String type, String body, Map<String, String> headers) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (type != null) { request.header("Content-Type", type); } headers.forEach(request::header);
		try (var client = client()) { return client.send(request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()); }
	}
	private static List<String> values(JsonNode object, String field) { return object.path(field).valueStream().map(JsonNode::asText).toList(); }
	private static JsonNode success(HttpResponse<String> response) { assertThat(response.statusCode()).as(response.body()).isEqualTo(200); assertSecurityHeaders(response); return JSON.readTree(response.body()); }
	private static void error(HttpResponse<String> response, int status) {
		assertThat(response.statusCode()).as(response.body()).isEqualTo(status); assertSecurityHeaders(response); assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
		assertThat(JSON.readTree(response.body()).path("error").asText()).isEqualTo("invalid_request");
	}
	private static Map<String, String> query(URI uri) {
		var result = new HashMap<String, String>(); for (String item : uri.getRawQuery().split("&")) { var parts = item.split("=", 2); result.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1], StandardCharsets.UTF_8)); } return result;
	}

}
