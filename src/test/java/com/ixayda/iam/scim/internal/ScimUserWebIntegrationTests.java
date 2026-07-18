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
import com.ixayda.iam.user.UserStatus;
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
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

	private static final JsonMapper JSON = JsonMapper.builder().build();

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
	void createsAnInactiveTenantScopedUserAndIgnoresReadOnlyAttributes() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		String request = """
				{
				  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
				  "id": "client-controlled-id",
				  "meta": {"location": "https://attacker.example.test/Users/1"},
				  "groups": [{"value": "client-controlled-group"}],
				  "userName": "provisioned-user",
				  "displayName": "Provisioned User",
				  "name": {
				    "formatted": "Provisioned Q. User",
				    "givenName": "Provisioned",
				    "familyName": "User"
				  },
				  "emails": [{"value": "Provisioned@Example.com"}],
				  "phoneNumbers": [{"value": "tel:+1-555-123-4500"}],
				  "active": false
				}
				""";

		MvcResult result = this.mockMvc.perform(post("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("tenant_id", other.id().toString())
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isCreated())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ScimUserSchema.URN))
			.andExpect(jsonPath("$.id").isNotEmpty())
			.andExpect(jsonPath("$.id").value(not("client-controlled-id")))
			.andExpect(jsonPath("$.userName").value("provisioned-user"))
			.andExpect(jsonPath("$.displayName").value("Provisioned User"))
			.andExpect(jsonPath("$.name.formatted").value("Provisioned Q. User"))
			.andExpect(jsonPath("$.emails[0].value").value("provisioned@example.com"))
			.andExpect(jsonPath("$.phoneNumbers[0].value").value("tel:+15551234500"))
			.andExpect(jsonPath("$.active").value(false))
			.andExpect(jsonPath("$.groups").doesNotExist())
			.andExpect(jsonPath("$.meta.location").isNotEmpty())
			.andReturn();

		JsonNode body = JSON.readTree(result.getResponse().getContentAsString());
		String id = body.get("id").stringValue();
		String location = "https://scim.example.test/scim/v2/Users/" + id;
		assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).isEqualTo(location);
		assertThat(result.getResponse().getHeader(HttpHeaders.CONTENT_LOCATION)).isEqualTo(location);
		assertThat(body.get("meta").get("location").stringValue()).isEqualTo(location);

		User stored = this.users.findById(tenant.id(), com.ixayda.iam.user.UserId.from(id)).orElseThrow();
		assertThat(stored.tenantId()).isEqualTo(tenant.id());
		assertThat(stored.status()).isEqualTo(UserStatus.DISABLED);
		assertThat(stored.identifiers()).containsExactly(LoginIdentifier.username("provisioned-user"),
				LoginIdentifier.email("Provisioned@Example.com"), LoginIdentifier.phone("+1-555-123-4500"));
		assertThat(this.users.findById(other.id(), stored.id())).isEmpty();
	}

	@Test
	void appliesResponseProjectionWhileAlwaysReturningTheCreatedLocation() throws Exception {
		Tenant tenant = createTenant();
		String request = """
				{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"projected-user"}
				""";

		this.mockMvc.perform(post("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("attributes", "userName")
			.contentType(MediaType.APPLICATION_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.id").isNotEmpty())
			.andExpect(jsonPath("$.userName").value("projected-user"))
			.andExpect(jsonPath("$.active").doesNotExist())
			.andExpect(jsonPath("$.meta.location").isNotEmpty())
			.andExpect(jsonPath("$.meta.created").doesNotExist());
	}

	@Test
	void returnsAConfidentialUniquenessConflictWithoutCommittingPartialUsers() throws Exception {
		Tenant tenant = createTenant();
		createUser(tenant.id(), "duplicate-user");
		createUser(tenant.id());
		String usernameConflict = """
				{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
				 "userName":"duplicate-user","emails":[{"value":"secret-conflict@example.com"}]}
				""";
		String emailConflict = """
				{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
				 "userName":"unique-email-user","emails":[{"value":"DUPLICATE-USER@example.COM"}]}
				""";
		String phoneConflict = """
				{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
				 "userName":"unique-phone-user","phoneNumbers":[{"value":"tel:+15551234567"}]}
				""";

		String authorization = bearer(token(tenant.id(), "scim.write"));
		assertCreateConflict(authorization, usernameConflict, "duplicate-user", "secret-conflict@example.com");
		assertCreateConflict(authorization, emailConflict, "DUPLICATE-USER@example.COM");
		assertCreateConflict(authorization, phoneConflict, "tel:+15551234567");

		assertThat(this.jdbcClient.sql("SELECT count(*) FROM users WHERE tenant_id = :tenantId")
			.param("tenantId", tenant.id().value())
			.query(Long.class)
			.single()).isEqualTo(2);
	}

	@Test
	void rejectsInvalidCreateBodiesWithoutReflectingTheirValues() throws Exception {
		Tenant tenant = createTenant();
		String authorization = bearer(token(tenant.id(), "scim.write"));

		assertCreateError(authorization, "{not-json", "invalidSyntax", null);
		assertCreateError(authorization, "", "invalidSyntax", null);
		assertCreateError(authorization, "{\"schemas\":null,\"userName\":\"null-schemas-user\"}",
				"invalidValue", null);
		assertCreateError(authorization, "{\"schemas\":[],\"userName\":\"empty-schemas-user\"}",
				"invalidValue", null);
		assertCreateError(authorization,
				"{\"schemas\":[\"" + ScimUserSchema.URN + "\"],\"userName\":\"alice\","
						+ "\"password\":\"secret-password-value\"}",
				"invalidValue", "secret-password-value");
		assertCreateError(authorization,
				"{\"schemas\":[\"urn:example:unsupported:User\"],\"userName\":\"alice\"}",
				"invalidValue", "urn:example:unsupported:User");
		assertCreateError(authorization,
				"{\"schemas\":[\"" + ScimUserSchema.URN
						+ "\",\"urn:example:unsupported:User\"],\"userName\":\"alice\"}",
				"invalidValue", "urn:example:unsupported:User");
		assertCreateError(authorization,
				"{\"schemas\":[\"" + ScimUserSchema.URN + "\",\"" + ScimUserSchema.URN
						+ "\"],\"userName\":\"duplicate-schemas-user\"}",
				"invalidValue", null);
		assertCreateError(authorization, "{\"userName\":\"missing-schemas-user\"}", "invalidValue", null);
		assertCreateError(authorization,
				"{\"schemas\":[\"" + ScimUserSchema.URN + "\"],\"userName\":\"alice\",\"emails\":\"bad-type\"}",
				"invalidValue", "bad-type");
		assertCreateError(authorization, "{\"schemas\":[\"" + ScimUserSchema.URN + "\"]}",
				"invalidValue", null);
	}

	@Test
	void rejectsScalarCoercionForCreateAttributesWithoutPersistingAUser() throws Exception {
		Tenant tenant = createTenant();
		String authorization = bearer(token(tenant.id(), "scim.write"));
		String prefix = "{\"schemas\":[\"" + ScimUserSchema.URN + "\"],";
		List<String> requests = List.of(
				prefix + "\"userName\":123}",
				prefix + "\"userName\":\"typed-display\",\"displayName\":123}",
				prefix + "\"userName\":\"typed-formatted\",\"name\":{\"formatted\":123}}",
				prefix + "\"userName\":\"typed-given\",\"name\":{\"givenName\":true}}",
				prefix + "\"userName\":\"typed-family\",\"name\":{\"familyName\":123.5}}",
				prefix + "\"userName\":\"typed-email\",\"emails\":[{\"value\":123}]}",
				prefix + "\"userName\":\"typed-phone\",\"phoneNumbers\":[{\"value\":123}]}",
				prefix + "\"userName\":\"typed-active-string\",\"active\":\"false\"}",
				prefix + "\"userName\":\"typed-active-empty\",\"active\":\"\"}",
				prefix + "\"userName\":\"typed-active-blank\",\"active\":\"   \"}",
				prefix + "\"userName\":\"typed-active-number\",\"active\":0}");

		for (String request : requests) {
			assertCreateError(authorization, request, "invalidValue", null);
		}

		assertThat(this.jdbcClient.sql("SELECT count(*) FROM users WHERE tenant_id = :tenantId")
			.param("tenantId", tenant.id().value())
			.query(Long.class)
			.single()).isZero();
	}

	@Test
	void rejectsCreatesForDisabledTenantsWithoutPersistingAUser() throws Exception {
		Tenant tenant = createTenant();
		this.tenants.disable(tenant.id());

		this.mockMvc.perform(post("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content("{\"schemas\":[\"" + ScimUserSchema.URN + "\"],\"userName\":\"disabled-tenant-user\"}"))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL));

		assertThat(this.jdbcClient.sql("SELECT count(*) FROM users WHERE tenant_id = :tenantId")
			.param("tenantId", tenant.id().value())
			.query(Long.class)
			.single()).isZero();
	}

	@Test
	void listsOnlyVisibleTenantUsersWithCanonicalPaginationMetadata() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User active = createUser(tenant.id(), "collection-active");
		User disabled = createUser(tenant.id(), "collection-disabled");
		User deleted = createUser(tenant.id(), "collection-deleted");
		createUser(other.id(), "collection-other");
		this.users.disable(tenant.id(), disabled.id());
		this.users.delete(tenant.id(), deleted.id());

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.queryParam("tenant_id", other.id().toString())
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, "https://scim.example.test/scim/v2/Users"))
			.andExpect(header().doesNotExist(HttpHeaders.LOCATION))
			.andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:ListResponse"))
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(1))
			.andExpect(jsonPath("$.itemsPerPage").value(2))
			.andExpect(jsonPath("$.Resources", hasSize(2)))
			.andExpect(jsonPath("$.Resources[*].id", containsInAnyOrder(active.id().toString(),
					disabled.id().toString())))
			.andExpect(jsonPath("$.Resources[*].active", containsInAnyOrder(true, false)))
			.andExpect(jsonPath("$.Resources[*].password").doesNotExist());
	}

	@Test
	void appliesBoundedPagingAndAttributeProjectionToUserCollections() throws Exception {
		Tenant tenant = createTenant();
		User first = createUser(tenant.id(), "page-first");
		User second = createUser(tenant.id(), "page-second");
		List<User> ordered = List.of(first, second).stream()
			.sorted(java.util.Comparator.comparing((user) -> user.id().toString()))
			.toList();
		String authorization = bearer(token(tenant.id(), "scim.read"));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "2")
			.queryParam("count", "1")
			.queryParam("attributes", "userName")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(2))
			.andExpect(jsonPath("$.itemsPerPage").value(1))
			.andExpect(jsonPath("$.Resources[0].id").value(ordered.get(1).id().toString()))
			.andExpect(jsonPath("$.Resources[0].userName").value(ordered.get(1).identifiers().getFirst().value()))
			.andExpect(jsonPath("$.Resources[0].active").doesNotExist())
			.andExpect(jsonPath("$.Resources[0].meta").doesNotExist());

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "-20")
			.queryParam("count", "-1")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(1))
			.andExpect(jsonPath("$.itemsPerPage").value(0))
			.andExpect(jsonPath("$.Resources", hasSize(0)));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "100")
			.queryParam("count", "101")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(100))
			.andExpect(jsonPath("$.itemsPerPage").value(0))
			.andExpect(jsonPath("$.Resources", hasSize(0)));
	}

	@Test
	void supportsExactCollectionFiltersAndRejectsUnsupportedQueries() throws Exception {
		Tenant tenant = createTenant();
		User alice = createUser(tenant.id(), "filter-alice");
		createUser(tenant.id(), "filter-bob");
		String authorization = bearer(token(tenant.id(), "scim.read"));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("filter", "userName EQ \"FILTER-ALICE\"")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(1))
			.andExpect(jsonPath("$.Resources[0].id").value(alice.id().toString()));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("filter", ScimUserSchema.URN + ":id eq \"" + alice.id() + "\"")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(1))
			.andExpect(jsonPath("$.Resources[0].userName").value("filter-alice"));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("filter", "emails.value eq \"secret-filter-value\"")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidFilter"))
			.andExpect(content().string(not(containsString("secret-filter-value"))));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("sortBy", "userName")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "9223372036854775808")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));

		this.mockMvc.perform(get("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.accept(SCIM_JSON))
			.andExpect(status().isForbidden());
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

	private void assertCreateError(String authorization, String request, String scimType, String secret)
			throws Exception {
		var response = this.mockMvc.perform(post("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("400"))
			.andExpect(jsonPath("$.scimType").value(scimType));
		if (secret != null) {
			response.andExpect(content().string(not(containsString(secret))));
		}
	}

	private void assertCreateConflict(String authorization, String request, String... secrets) throws Exception {
		var response = this.mockMvc.perform(post("/scim/v2/Users")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isConflict())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("409"))
			.andExpect(jsonPath("$.scimType").value("uniqueness"));
		for (String secret : secrets) {
			response.andExpect(content().string(not(containsString(secret))));
		}
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
