package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientRegistration;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.ClientTokenPolicy;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.CreateClientRequest;
import com.ixayda.iam.tenant.TenantId;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
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

	@Autowired
	private ClientOperations clients;

	@Autowired
	private JdbcClient jdbcClient;

	private ClientId clientToDelete;

	@AfterEach
	void deleteClient() {
		if (this.clientToDelete != null) {
			this.jdbcClient.sql("DELETE FROM oauth_clients WHERE client_id = :clientId")
				.param("clientId", this.clientToDelete.value())
				.update();
		}
	}

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

	@Test
	void rejectsUnsupportedAuthorizationRequestParameters() throws Exception {
		String clientIdentifier = "authorization-parameter-client";
		try (ClientRegistration registration = this.clients.create(TenantId.DEFAULT,
				publicClientRequest(clientIdentifier))) {
			this.clientToDelete = registration.client().id();
		}
		HttpResponse<String> response = get(
				"/oauth2/authorize?response_type=code&client_id=" + clientIdentifier
						+ "&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=openid"
						+ "&state=state-value&code_challenge=" + "A".repeat(43)
						+ "&code_challenge_method=S256&resource=https%3A%2F%2Fapi.example.test",
				"application/json");

		assertThat(response.statusCode()).isEqualTo(400);
	}

	private static CreateClientRequest publicClientRequest(String identifier) {
		return new CreateClientRequest(new ClientIdentifier(identifier), "Authorization Parameter Client",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE,
				Set.of(new ClientRedirectUri("https://client.example.test/callback")), Set.of(),
				Set.of(new ClientScope("openid")), ClientTokenPolicy.secureDefaults());
	}

	private HttpResponse<String> get(String path, String accept) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + path))
			.header("Accept", accept)
			.GET()
			.build();
		return this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
	}

}
