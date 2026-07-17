package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class AuthorizationServerWebSecurityIntegrationTests extends ApplicationIntegrationTest {

	private static final String ISSUER = "https://issuer.example.test";

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private final HttpClient httpClient = HttpClient.newBuilder()
		.followRedirects(HttpClient.Redirect.NEVER)
		.build();

	@LocalServerPort
	private int port;

	@Test
	void exposesOpenIdProviderMetadata() throws Exception {
		HttpResponse<String> response = get("/.well-known/openid-configuration", "application/json");

		assertThat(response.statusCode()).isEqualTo(200);
		JsonNode metadata = JSON.readTree(response.body());
		assertThat(metadata.get("issuer").stringValue()).isEqualTo(ISSUER);
		assertThat(metadata.get("authorization_endpoint").stringValue()).isEqualTo(ISSUER + "/oauth2/authorize");
		assertThat(metadata.get("token_endpoint").stringValue()).isEqualTo(ISSUER + "/oauth2/token");
		assertThat(metadata.get("jwks_uri").stringValue()).isEqualTo(ISSUER + "/oauth2/jwks");
	}

	@Test
	void publishesOnlyTheActivePublicSigningKey() throws Exception {
		HttpResponse<String> response = get("/oauth2/jwks", "application/json");

		assertThat(response.statusCode()).isEqualTo(200);
		JWKSet jwkSet = JWKSet.load(
				new ByteArrayInputStream(response.body().getBytes(StandardCharsets.UTF_8)));
		assertThat(jwkSet.getKeys()).singleElement().satisfies((key) -> {
			assertThat(key.isPrivate()).isFalse();
			assertThat(key.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
			assertThat(key.getKeyID()).matches("[A-Za-z0-9_-]{43}");
		});
	}

	@Test
	void keepsNonProtocolApplicationPathsDenied() throws Exception {
		HttpResponse<String> response = get("/not-a-protocol-endpoint", "text/html");

		assertThat(response.statusCode()).isEqualTo(403);
	}

	private HttpResponse<String> get(String path, String accept) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + path))
			.header("Accept", accept)
			.GET()
			.build();
		return this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
	}

}
