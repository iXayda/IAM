package com.ixayda.iam.security;

import java.nio.charset.StandardCharsets;

import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import static org.assertj.core.api.Assertions.*;

class IdentityDiscoveryRequestFilterTests {

	@ParameterizedTest
	@ValueSource(strings = { "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" })
	void unknownLengthBodiesAreRejectedBeforePublishingMetadata(String path) throws Exception {
		var request = new MockHttpServletRequest("GET", path) {
			@Override public long getContentLengthLong() { return -1; }
			@Override public int getContentLength() { return -1; }
		};
		request.setServletPath(path); request.setContent("private-body".getBytes(StandardCharsets.UTF_8)); var response = new MockHttpServletResponse();
		var filter = new IdentityDiscoveryRequestFilter(AuthorizationServerSettings.builder().issuer("https://iam.example").build());
		filter.doFilter(request, response, (req, res) -> fail("Metadata cannot fall through to another endpoint"));
		assertThat(response.getStatus()).isEqualTo(400); assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_request\"}");
		assertThat(request.getSession(false)).isNull(); assertThat(AuthorizationServerContextHolder.getContext()).isNull();
	}

	@ParameterizedTest
	@CsvSource({
			"https://iam.example, /.well-known/openid-configuration", "https://iam.example/, /.well-known/openid-configuration",
			"https://iam.example, /.well-known/oauth-authorization-server", "https://iam.example/, /.well-known/oauth-authorization-server",
			"https://iam.example:8443, /.well-known/openid-configuration", "https://[::1]:8443/, /.well-known/oauth-authorization-server" })
	void advertisedUrlsRespectTheConfiguredIssuerWithoutDuplicatingTrailingSlashes(String issuer, String path) throws Exception {
		var request = new MockHttpServletRequest("GET", path); request.setServletPath(path);
		request.setServerName("untrusted.example"); var response = new MockHttpServletResponse();
		var filter = new IdentityDiscoveryRequestFilter(AuthorizationServerSettings.builder().issuer(issuer).build());
		filter.doFilter(request, response, (req, res) -> fail("The official metadata filter must finish the response"));
		var metadata = new JsonMapper().readTree(response.getContentAsString());
		assertThat(metadata.path("issuer").asText()).isEqualTo(issuer);
		assertThat(metadata.path("token_endpoint").asText()).isEqualTo(issuer.replaceFirst("/$", "") + "/oauth2/token");
		assertThat(metadata.path("authorization_endpoint").asText()).isEqualTo(issuer.replaceFirst("/$", "") + "/oauth2/authorize");
		assertThat(AuthorizationServerContextHolder.getContext()).isNull(); assertThat(request.getSession(false)).isNull();
	}

}
