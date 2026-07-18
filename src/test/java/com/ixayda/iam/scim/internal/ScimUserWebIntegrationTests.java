package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class ScimUserWebIntegrationTests extends ApplicationIntegrationTest {

	private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

	private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

	private static final String NOT_FOUND_DETAIL = "The requested SCIM user was not found.";

	private static final String ISSUER = "https://issuer.example.test";

	private static final String AUDIENCE = "https://scim.example.test/scim/v2";

	private static final String CLIENT_ID = "scim-user-reader";

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	private final HttpClient httpClient = HttpClient.newHttpClient();

	@LocalServerPort
	private int port;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.forEach((tenantId) -> {
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
		});
	}

	@Test
	void retrievesATenantScopedUserWithCanonicalMetadata() throws Exception {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id());
		String location = "https://scim.example.test/scim/v2/Users/" + user.id();

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimUserSchema.URN))
			.andExpect(jsonPath("$.id").value(user.id().toString()))
			.andExpect(jsonPath("$.userName").value("alice"))
			.andExpect(jsonPath("$.displayName").value("Alice Jensen"))
			.andExpect(jsonPath("$.name.formatted").value("Alice Q. Jensen"))
			.andExpect(jsonPath("$.name.givenName").value("Alice"))
			.andExpect(jsonPath("$.name.familyName").value("Jensen"))
			.andExpect(jsonPath("$.emails[0].value").value("alice@example.com"))
			.andExpect(jsonPath("$.phoneNumbers[0].value").value("tel:+15551234567"))
			.andExpect(jsonPath("$.active").value(true))
			.andExpect(jsonPath("$.meta.resourceType").value("User"))
			.andExpect(jsonPath("$.meta.created").exists())
			.andExpect(jsonPath("$.meta.lastModified").exists())
			.andExpect(jsonPath("$.meta.location").value(location))
			.andExpect(jsonPath("$.meta.version").doesNotExist())
			.andExpect(jsonPath("$.externalId").doesNotExist())
			.andExpect(jsonPath("$.password").doesNotExist())
			.andExpect(jsonPath("$.groups").doesNotExist());
	}

	@Test
	void supportsHeadWithoutReturningARepresentation() throws Exception {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id());
		String location = "https://scim.example.test/scim/v2/Users/" + user.id();
		URI endpoint = URI.create("http://127.0.0.1:" + this.port + "/scim/v2/Users/" + user.id());
		HttpRequest request = HttpRequest.newBuilder(endpoint)
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.header(HttpHeaders.ACCEPT, SCIM_JSON.toString())
			.method("HEAD", HttpRequest.BodyPublishers.noBody())
			.build();

		HttpResponse<byte[]> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.headers().firstValue(HttpHeaders.CONTENT_LOCATION)).hasValue(location);
		assertThat(response.body()).isEmpty();
	}

	@Test
	void appliesIncludedAndExcludedAttributeParameters() throws Exception {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id());
		String authorization = bearer(token(tenant.id(), "scim.read"));

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "displayName,name.givenName")
			.queryParam("attributes", ScimUserSchema.URN + ":emails.value")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.schemas[0]").value(ScimUserSchema.URN))
			.andExpect(jsonPath("$.id").value(user.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Alice Jensen"))
			.andExpect(jsonPath("$.name.givenName").value("Alice"))
			.andExpect(jsonPath("$.emails[0].value").value("alice@example.com"))
			.andExpect(jsonPath("$.userName").doesNotExist())
			.andExpect(jsonPath("$.name.formatted").doesNotExist())
			.andExpect(jsonPath("$.active").doesNotExist())
			.andExpect(jsonPath("$.meta").doesNotExist());

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("excludedAttributes", "EMAILS,name.familyName,meta.created")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.userName").value("alice"))
			.andExpect(jsonPath("$.emails").doesNotExist())
			.andExpect(jsonPath("$.name.givenName").value("Alice"))
			.andExpect(jsonPath("$.name.familyName").doesNotExist())
			.andExpect(jsonPath("$.meta.created").doesNotExist())
			.andExpect(jsonPath("$.meta.lastModified").exists());
	}

	@Test
	void rejectsInvalidAttributeSelectionsWithoutReflectingTheirValues() throws Exception {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id());
		String authorization = bearer(token(tenant.id(), "scim.read"));

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "userName")
			.queryParam("excludedAttributes", "emails")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "unknownSecret")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.scimType").value("invalidValue"))
			.andExpect(content().string(not(containsString("unknownSecret"))));
	}

	@Test
	void returnsTheSameNotFoundResponseAcrossTenantAndLifecycleBoundaries() throws Exception {
		Tenant owner = createTenant();
		Tenant other = createTenant();
		Tenant disabled = createTenant();
		User visible = createUser(owner.id());
		User deleted = createUser(owner.id(), "deleted-user");
		User disabledTenantUser = createUser(disabled.id(), "disabled-tenant-user");
		this.users.delete(owner.id(), deleted.id());
		this.tenants.disable(disabled.id());

		String missing = responseBody(owner.id(), UUID.randomUUID().toString());
		String malformed = responseBody(owner.id(), "not-a-uuid");
		String nonCanonical = responseBody(owner.id(), visible.id().toString().toUpperCase(Locale.ROOT));
		String crossTenant = responseBody(other.id(), visible.id().toString());
		String deletedBody = responseBody(owner.id(), deleted.id().toString());
		String disabledTenantBody = responseBody(disabled.id(), disabledTenantUser.id().toString());

		assertThat(List.of(malformed, nonCanonical, crossTenant, deletedBody, disabledTenantBody)).containsOnly(missing);
		assertThat(missing).contains(NOT_FOUND_DETAIL).doesNotContain(visible.id().toString());
	}

	@Test
	void mapsDisabledUsersAsInactiveAndRequiresReadScope() throws Exception {
		Tenant tenant = createTenant();
		User user = createUser(tenant.id());
		this.users.disable(tenant.id(), user.id());

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.active").value(false));

		this.mockMvc.perform(get("/scim/v2/Users/{id}", user.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.accept(SCIM_JSON))
			.andExpect(status().isForbidden())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
					"Bearer error=\"insufficient_scope\", scope=\"scim.read\""));
	}

	private String responseBody(TenantId tenantId, String userId) throws Exception {
		MvcResult result = this.mockMvc.perform(get("/scim/v2/Users/{id}", userId)
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenantId, "scim.read")))
			.accept(SCIM_JSON))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("404"))
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL))
			.andReturn();
		return result.getResponse().getContentAsString();
	}

	private Tenant createTenant() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("scim-user-" + suffix, "SCIM User Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId) {
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("alice"),
						LoginIdentifier.email("alice@Example.com"),
						LoginIdentifier.phone("+1 (555) 123-4567")),
						new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen")));
	}

	private User createUser(TenantId tenantId, String username) {
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username),
						LoginIdentifier.email(username + "@Example.com")),
						new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen")));
	}

	private String token(TenantId tenantId, String scope) {
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
			.issuer(ISSUER)
			.subject(CLIENT_ID)
			.audience(List.of(AUDIENCE))
			.issuedAt(now.minusSeconds(5))
			.expiresAt(now.plusSeconds(295))
			.notBefore(now.minusSeconds(5))
			.claim("tenant_id", tenantId.toString())
			.claim("client_id", CLIENT_ID)
			.claim(OAuth2ParameterNames.SCOPE, List.of(scope))
			.build();
		JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
		return this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	private static String bearer(String token) {
		return "Bearer " + token;
	}

}
