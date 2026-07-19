package com.ixayda.iam.scim.internal;

import java.time.Instant;
import java.util.List;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@Import(ScimWebSecurityIntegrationTests.ProvisioningProbeController.class)
class ScimWebSecurityIntegrationTests extends ApplicationIntegrationTest {

	private static final String ISSUER = "https://issuer.example.test";

	private static final String AUDIENCE = "https://scim.example.test/scim/v2";

	private static final String TENANT_ID = "00000000-0000-0000-0000-000000000001";

	private static final String CLIENT_ID = "scim-security-client";

	private static final String USERS_PATH = "/scim/v2/Users";

	private static final String GROUPS_PATH = "/scim/v2/Groups";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Test
	void authorizesReadAndWriteScopesIndependently() throws Exception {
		this.mockMvc.perform(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.read"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(post(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(get(GROUPS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.read"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(post(GROUPS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(put(USERS_PATH + "/user-1")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(patch(USERS_PATH + "/user-1")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))))
			.andExpect(status().isNoContent());
		this.mockMvc.perform(delete(USERS_PATH + "/user-1")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))))
			.andExpect(status().isNotFound());

		assertForbidden(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))), "scim.read");
		assertForbidden(post(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.read"))), "scim.write");
		assertForbidden(delete(USERS_PATH + "/user-1")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.read"))), "scim.write");
		assertForbidden(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token(null))), "scim.read");
		assertForbiddenWithoutScope(post(USERS_PATH + "/user-1")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))));
		assertForbiddenWithoutScope(put(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token("scim.write"))));
		assertForbiddenWithoutScope(get(USERS_PATH + "/user-1/nested")
			.header(HttpHeaders.AUTHORIZATION, bearer(token("scim.read"))));
	}

	@Test
	void rejectsMissingMalformedAndTamperedBearerTokens() throws Exception {
		assertUnauthorized(get(USERS_PATH), "Bearer");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"),
				"Bearer error=\"invalid_token\"");
		String token = token("scim.read");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(tamperSignature(token))),
				"Bearer error=\"invalid_token\"");
		assertBearerError(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, bearer(token), bearer(token)),
				400, "Bearer error=\"invalid_request\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION, "Basic Zm9vOmJhcg=="), "Bearer");
		assertUnauthorized(get(USERS_PATH).queryParam("access_token", token), "Bearer");
		assertUnauthorized(post(USERS_PATH).param("access_token", token), "Bearer");
	}

	@Test
	void rejectsTokensOutsideTheServiceTokenProfile() throws Exception {
		Instant now = Instant.now();
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token("https://wrong-issuer.example.test", List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID,
						now.minusSeconds(5), now.plusSeconds(295), now.minusSeconds(5), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of("https://api.example.test"), TENANT_ID, CLIENT_ID, CLIENT_ID,
						now.minusSeconds(5), now.plusSeconds(295), now.minusSeconds(5), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, "another-client", now.minusSeconds(5),
						now.plusSeconds(295), now.minusSeconds(5), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID, now.minusSeconds(400),
						now.minusSeconds(100), now.minusSeconds(400), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID, now.minusSeconds(5),
						now.plusSeconds(295), now.plusSeconds(120), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID, now.minusSeconds(5),
						now.plusSeconds(295), null, List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
		assertUnauthorized(get(USERS_PATH).header(HttpHeaders.AUTHORIZATION,
				bearer(token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID, now.minusSeconds(331),
						now.minusSeconds(31), now.minusSeconds(331), List.of("scim.read")))),
				"Bearer error=\"invalid_token\"");
	}

	@Test
	void authenticatesInvalidBearerCredentialsBeforeServingPublicDiscovery() throws Exception {
		this.mockMvc.perform(get("/scim/v2/ServiceProviderConfig")
			.header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
			.andExpect(status().isUnauthorized())
			.andExpect(content().contentTypeCompatibleWith(ScimMediaTypes.SCIM_JSON))
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""));
	}

	private String token(String scope) {
		Instant now = Instant.now();
		return token(ISSUER, List.of(AUDIENCE), TENANT_ID, CLIENT_ID, CLIENT_ID, now.minusSeconds(5),
				now.plusSeconds(295), now.minusSeconds(5), scope == null ? null : List.of(scope));
	}

	private String token(String issuer, List<String> audience, String tenantId, String clientId, String subject,
			Instant issuedAt, Instant expiresAt, Instant notBefore, List<String> scopes) {
		JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
			.issuer(issuer)
			.subject(subject)
			.audience(audience)
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.claim("tenant_id", tenantId)
			.claim("client_id", clientId);
		if (notBefore != null) {
			claims.notBefore(notBefore);
		}
		if (scopes != null) {
			claims.claim(OAuth2ParameterNames.SCOPE, scopes);
		}
		JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
		return this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
	}

	private void assertUnauthorized(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
			String challenge)
			throws Exception {
		assertBearerError(request, 401, challenge);
	}

	private void assertBearerError(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
			int expectedStatus, String challenge)
			throws Exception {
		this.mockMvc.perform(request)
			.andExpect(status().is(expectedStatus))
			.andExpect(content().contentTypeCompatibleWith(ScimMediaTypes.SCIM_JSON))
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, challenge))
			.andExpect(jsonPath("$.status").value(Integer.toString(expectedStatus)))
			.andExpect(content().string(not(containsString("Jwt"))));
	}

	private void assertForbidden(org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request,
			String requiredScope)
			throws Exception {
		this.mockMvc.perform(request)
			.andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(ScimMediaTypes.SCIM_JSON))
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
					"Bearer error=\"insufficient_scope\", scope=\"" + requiredScope + "\""))
				.andExpect(jsonPath("$.status").value("403"));
	}

	private void assertForbiddenWithoutScope(
			org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request) throws Exception {
		this.mockMvc.perform(request)
			.andExpect(status().isForbidden())
			.andExpect(content().contentTypeCompatibleWith(ScimMediaTypes.SCIM_JSON))
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
			.andExpect(jsonPath("$.status").value("403"));
	}

	private static String bearer(String token) {
		return "Bearer " + token;
	}

	private static String tamperSignature(String token) {
		String[] segments = token.split("\\.");
		int index = segments[2].length() / 2;
		char replacement = segments[2].charAt(index) == 'A' ? 'B' : 'A';
		segments[2] = segments[2].substring(0, index) + replacement + segments[2].substring(index + 1);
		return String.join(".", segments);
	}

	@RestController
	static class ProvisioningProbeController {

		@GetMapping({ USERS_PATH, GROUPS_PATH })
		ResponseEntity<Void> read() {
			return ResponseEntity.noContent().build();
		}

		@PostMapping({ USERS_PATH, GROUPS_PATH })
		ResponseEntity<Void> write() {
			return ResponseEntity.noContent().build();
		}

		@RequestMapping(path = USERS_PATH + "/{id}", method = { RequestMethod.PUT, RequestMethod.PATCH })
		ResponseEntity<Void> writeUserResource() {
			return ResponseEntity.noContent().build();
		}

		@RequestMapping(path = GROUPS_PATH + "/{id}",
				method = { RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE })
		ResponseEntity<Void> writeResource() {
			return ResponseEntity.noContent().build();
		}

	}

}
