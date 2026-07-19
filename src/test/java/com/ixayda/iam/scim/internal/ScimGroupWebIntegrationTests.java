package com.ixayda.iam.scim.internal;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
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
class ScimGroupWebIntegrationTests extends ApplicationIntegrationTest {

	private static final MediaType SCIM_JSON = MediaType.parseMediaType("application/scim+json");

	private static final String ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

	private static final String NOT_FOUND_DETAIL = "The requested SCIM group was not found.";

	private static final String ISSUER = "https://issuer.example.test";

	private static final String AUDIENCE = "https://scim.example.test/scim/v2";

	private static final String CLIENT_ID = "scim-group-reader";

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private GroupOperations groups;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.forEach((tenantId) -> {
			this.jdbcClient.sql("DELETE FROM group_memberships WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM groups WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
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
	void retrievesATenantScopedGroupWithCanonicalMembersAndMetadata() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		Group created = createGroup(tenant.id(), "Platform Administrators");
		User first = createUser(tenant.id(), "group-first");
		User second = createUser(tenant.id(), "group-second");
		Group populated = this.groups.replaceMembers(tenant.id(), created.id(), created.version(),
				Set.of(second.id(), first.id()));
		String location = "https://scim.example.test/scim/v2/Groups/" + populated.id();
		String firstLocation = "https://scim.example.test/scim/v2/Users/" + first.id();
		String secondLocation = "https://scim.example.test/scim/v2/Users/" + second.id();

		this.mockMvc.perform(get("/scim/v2/Groups/{id}", populated.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.queryParam("tenant_id", other.id().toString())
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(populated.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Platform Administrators"))
			.andExpect(jsonPath("$.members", hasSize(2)))
			.andExpect(jsonPath("$.members[*].value",
					containsInAnyOrder(first.id().toString(), second.id().toString())))
			.andExpect(jsonPath("$.members[*].type", containsInAnyOrder("User", "User")))
			.andExpect(jsonPath("$.members[*].$ref", containsInAnyOrder(firstLocation, secondLocation)))
			.andExpect(jsonPath("$.members[*].display").doesNotExist())
			.andExpect(jsonPath("$.meta.resourceType").value("Group"))
			.andExpect(jsonPath("$.meta.created").exists())
			.andExpect(jsonPath("$.meta.lastModified").exists())
			.andExpect(jsonPath("$.meta.location").value(location))
			.andExpect(jsonPath("$.meta.version").doesNotExist());
	}

	@Test
	void createsATenantScopedGroupWithCanonicalMembersAndMetadata() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User first = createUser(tenant.id(), "create-first");
		User second = createUser(tenant.id(), "create-second");
		String request = """
				{
				  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				  "id": 42,
				  "meta": "ignored",
				  "displayName": "Platform Operators",
				  "members": [
				    {"value": "%s", "type": "user", "$ref": "Users/%s"},
				    {"value": "%s", "$ref": "/scim/v2/Users/%s"},
				    {"value": "%s", "$ref": "https://scim.example.test/scim/v2/Users/%s"}
				  ]
				}
				""".formatted(first.id().toString().toUpperCase(Locale.ROOT), first.id(), second.id(), second.id(),
				first.id(), first.id());

		MvcResult result = this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("tenant_id", other.id().toString())
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isCreated())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").isNotEmpty())
			.andExpect(jsonPath("$.displayName").value("Platform Operators"))
			.andExpect(jsonPath("$.members", hasSize(2)))
			.andExpect(jsonPath("$.members[*].value",
					containsInAnyOrder(first.id().toString(), second.id().toString())))
			.andExpect(jsonPath("$.members[*].type", containsInAnyOrder("User", "User")))
			.andExpect(jsonPath("$.meta.resourceType").value("Group"))
			.andExpect(jsonPath("$.meta.created").exists())
			.andExpect(jsonPath("$.meta.lastModified").exists())
			.andExpect(jsonPath("$.meta.version").doesNotExist())
			.andReturn();

		JsonNode body = JSON.readTree(result.getResponse().getContentAsString());
		String id = body.get("id").stringValue();
		String location = "https://scim.example.test/scim/v2/Groups/" + id;
		assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).isEqualTo(location);
		assertThat(result.getResponse().getHeader(HttpHeaders.CONTENT_LOCATION)).isEqualTo(location);
		assertThat(body.get("meta").get("location").stringValue()).isEqualTo(location);
		Group stored = this.groups.findById(tenant.id(), com.ixayda.iam.group.GroupId.from(id)).orElseThrow();
		assertThat(stored.displayName()).isEqualTo("Platform Operators");
		assertThat(stored.version()).isZero();
		assertThat(this.groups.findById(other.id(), stored.id())).isEmpty();
	}

	@Test
	void appliesCreateProjectionWhileAlwaysReturningTheCreatedLocation() throws Exception {
		Tenant tenant = createTenant();
		String request = """
				{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Projected Create"}
				""";

		this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("attributes", "displayName")
			.contentType(MediaType.APPLICATION_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").isNotEmpty())
			.andExpect(jsonPath("$.displayName").value("Projected Create"))
			.andExpect(jsonPath("$.members").doesNotExist())
			.andExpect(jsonPath("$.meta.location").isNotEmpty())
			.andExpect(jsonPath("$.meta.created").doesNotExist());
	}

	@Test
	void acceptsDisabledAndLockedMembers() throws Exception {
		Tenant tenant = createTenant();
		User disabled = createUser(tenant.id(), "create-disabled");
		User locked = createUser(tenant.id(), "create-locked");
		this.users.disable(tenant.id(), disabled.id());
		this.users.lock(tenant.id(), locked.id());
		String request = """
				{
				  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
				  "displayName":"Non-active Members",
				  "members":[{"value":"%s"},{"value":"%s"}]
				}
				""".formatted(disabled.id(), locked.id());

		this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.members[*].value",
					containsInAnyOrder(disabled.id().toString(), locked.id().toString())));
	}

	@Test
	void rejectsInvalidCreateRepresentationsWithoutPersistingGroups() throws Exception {
		Tenant tenant = createTenant();
		User member = createUser(tenant.id(), "invalid-create-member");
		long initialGroupCount = groupCount(tenant.id());
		List<String> invalidRequests = List.of(
				"{}",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"Invalid"}
						""",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","externalId":"secret-external"}
						""",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","secretUnknown":true}
						""",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","members":[{"type":"User"}]}
						""",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","members":[{"value":"%s","display":"secret-display"}]}
						""".formatted(member.id()),
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","members":[{"value":"%s","type":"Group"}]}
						""".formatted(member.id()),
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Invalid","members":[{"value":"%s","$ref":"https://external.example.test/scim/v2/Users/%s?secret=query"}]}
						""".formatted(member.id(), member.id()));

		for (String request : invalidRequests) {
			this.mockMvc.perform(post("/scim/v2/Groups")
				.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
				.contentType(SCIM_JSON)
				.accept(SCIM_JSON)
				.content(request))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
				.andExpect(jsonPath("$.scimType").value("invalidValue"))
				.andExpect(content().string(not(containsString("secret"))));
		}
		assertThat(groupCount(tenant.id())).isEqualTo(initialGroupCount);
	}

	@Test
	void rejectsDuplicateCreateAttributesAsInvalidSyntax() throws Exception {
		Tenant tenant = createTenant();
		User member = createUser(tenant.id(), "duplicate-create-member");
		List<String> duplicateRequests = List.of(
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"First","displayName":"Second"}
						""",
				"""
						{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Duplicate Member","members":[{"value":"%s","value":"%s"}]}
						""".formatted(member.id(), UUID.randomUUID()));

		for (String request : duplicateRequests) {
			this.mockMvc.perform(post("/scim/v2/Groups")
				.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
				.contentType(SCIM_JSON)
				.accept(SCIM_JSON)
				.content(request))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
				.andExpect(jsonPath("$.status").value("400"))
				.andExpect(jsonPath("$.scimType").value("invalidSyntax"));
		}
	}

	@Test
	void hidesUnavailableMembersAndRollsBackEveryCreateSideEffect() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User valid = createUser(tenant.id(), "rollback-member");
		User crossTenant = createUser(other.id(), "cross-tenant-member");
		User deleted = createUser(tenant.id(), "deleted-member");
		this.users.delete(tenant.id(), deleted.id());
		UserId missing = new UserId(new UUID(Long.MAX_VALUE, Long.MAX_VALUE));
		long groupCount = groupCount(tenant.id());
		long membershipCount = membershipCount(tenant.id());
		long validVersion = this.users.findById(tenant.id(), valid.id()).orElseThrow().version();
		String request = """
				{
				  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
				  "displayName":"Atomic Create",
				  "members":[{"value":"%s"},{"value":"%s"}]
				}
				""".formatted(valid.id(), missing);

		invalidMemberResponse(tenant.id(), request);
		assertThat(groupCount(tenant.id())).isEqualTo(groupCount);
		assertThat(membershipCount(tenant.id())).isEqualTo(membershipCount);
		assertThat(this.users.findById(tenant.id(), valid.id()).orElseThrow().version()).isEqualTo(validVersion);

		String missingBody = invalidMemberResponse(tenant.id(), memberRequest(missing));
		String crossTenantBody = invalidMemberResponse(tenant.id(), memberRequest(crossTenant.id()));
		String deletedBody = invalidMemberResponse(tenant.id(), memberRequest(deleted.id()));
		assertThat(List.of(crossTenantBody, deletedBody)).containsOnly(missingBody);
	}

	@Test
	void listsTenantScopedGroupsWithPaginationFiltersAndProjectedMembers() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		Group first = createGroup(tenant.id(), "Directory Group");
		Group second = createGroup(tenant.id(), "directory group");
		Group deleted = createGroup(tenant.id(), "DIRECTORY GROUP");
		createGroup(other.id(), "Directory Group");
		User member = createUser(tenant.id(), "directory-member");
		first = this.groups.replaceMembers(tenant.id(), first.id(), first.version(), Set.of(member.id()));
		second = this.groups.replaceMembers(tenant.id(), second.id(), second.version(), Set.of(member.id()));
		this.groups.delete(tenant.id(), deleted.id(), deleted.version());
		String authorization = bearer(token(tenant.id(), "scim.read"));
		String collectionLocation = "https://scim.example.test/scim/v2/Groups";

		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "1")
			.queryParam("count", "100")
			.queryParam("filter", "displayName eq \"dIrEcToRy GrOuP\"")
			.queryParam("attributes", "displayName,members.value")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, collectionLocation))
			.andExpect(header().doesNotExist(HttpHeaders.LOCATION))
			.andExpect(jsonPath("$.schemas[0]").value("urn:ietf:params:scim:api:messages:2.0:ListResponse"))
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(1))
			.andExpect(jsonPath("$.itemsPerPage").value(2))
			.andExpect(jsonPath("$.Resources", hasSize(2)))
			.andExpect(jsonPath("$.Resources[*].id",
					containsInAnyOrder(first.id().toString(), second.id().toString())))
			.andExpect(jsonPath("$.Resources[*].displayName",
					containsInAnyOrder("Directory Group", "directory group")))
			.andExpect(jsonPath("$.Resources[*].members[0].value",
					containsInAnyOrder(member.id().toString(), member.id().toString())))
			.andExpect(jsonPath("$.Resources[*].members[0].type").doesNotExist())
			.andExpect(jsonPath("$.Resources[*].members[0].$ref").doesNotExist());

		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "2")
			.queryParam("count", "1")
			.queryParam("filter", "displayName eq \"directory group\"")
			.queryParam("excludedAttributes", "members.value,members.type,members.$ref")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.startIndex").value(2))
			.andExpect(jsonPath("$.itemsPerPage").value(1))
			.andExpect(jsonPath("$.Resources", hasSize(1)))
			.andExpect(jsonPath("$.Resources[0].members").doesNotExist());

		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("count", "0")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(2))
			.andExpect(jsonPath("$.itemsPerPage").value(0))
			.andExpect(jsonPath("$.Resources", hasSize(0)));
		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("startIndex", "100")
			.queryParam("filter", "id eq \"" + first.id() + "\"")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totalResults").value(1))
			.andExpect(jsonPath("$.startIndex").value(100))
			.andExpect(jsonPath("$.itemsPerPage").value(0))
			.andExpect(jsonPath("$.Resources", hasSize(0)));
	}

	@Test
	void validatesGroupCollectionQueriesAndRequiresReadScope() throws Exception {
		Tenant tenant = createTenant();
		String authorization = bearer(token(tenant.id(), "scim.read"));

		for (String query : List.of("filter=displayName%20co%20%22secret-filter-value%22", "sortBy=displayName",
				"startIndex=not-a-number")) {
			this.mockMvc.perform(get("/scim/v2/Groups?" + query)
				.header(HttpHeaders.AUTHORIZATION, authorization)
				.accept(SCIM_JSON))
				.andExpect(status().isBadRequest())
				.andExpect(content().string(not(containsString("secret-filter-value"))));
		}

		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.accept(SCIM_JSON))
			.andExpect(status().isForbidden())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
					"Bearer error=\"insufficient_scope\", scope=\"scim.read\""));
		this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content("{\"schemas\":[\"" + ScimGroupSchema.URN + "\"],\"displayName\":\"Denied\"}"))
			.andExpect(status().isForbidden())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
					"Bearer error=\"insufficient_scope\", scope=\"scim.write\""));

		this.tenants.disable(tenant.id());
		this.mockMvc.perform(get("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.accept(SCIM_JSON))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL));
		this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content("{\"schemas\":[\"" + ScimGroupSchema.URN + "\"],\"displayName\":\"Disabled\"}"))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL));
	}

	@Test
	void supportsGroupAttributeProjectionAndRejectsInvalidSelections() throws Exception {
		Tenant tenant = createTenant();
		Group created = createGroup(tenant.id(), "Projected Group");
		User member = createUser(tenant.id(), "projected-member");
		Group populated = this.groups.replaceMembers(tenant.id(), created.id(), created.version(), Set.of(member.id()));
		String authorization = bearer(token(tenant.id(), "scim.read"));

		this.mockMvc.perform(get("/scim/v2/Groups/{id}", populated.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "displayName,members.value,meta.created")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(populated.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Projected Group"))
			.andExpect(jsonPath("$.members[0].value").value(member.id().toString()))
			.andExpect(jsonPath("$.members[0].type").doesNotExist())
			.andExpect(jsonPath("$.members[0].$ref").doesNotExist())
			.andExpect(jsonPath("$.meta.created").exists())
			.andExpect(jsonPath("$.meta.lastModified").doesNotExist())
			.andExpect(jsonPath("$.meta.location").doesNotExist());
		this.mockMvc.perform(get("/scim/v2/Groups/{id}", populated.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("excludedAttributes", "members.value,members.type,members.$ref")
			.accept(SCIM_JSON))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.members").doesNotExist());

		for (String selection : List.of("unknown-secret", ScimUserSchema.URN + ":userName",
				"members[value eq \"secret\"]")) {
			this.mockMvc.perform(get("/scim/v2/Groups/{id}", populated.id())
				.header(HttpHeaders.AUTHORIZATION, authorization)
				.queryParam("attributes", selection)
				.accept(SCIM_JSON))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.scimType").value("invalidValue"))
				.andExpect(content().string(not(containsString("secret"))));
		}
	}

	@Test
	void hidesInvisibleGroupsAndRequiresReadScope() throws Exception {
		Tenant owner = createTenant();
		Tenant other = createTenant();
		Tenant disabled = createTenant();
		Group visible = createGroup(owner.id(), "Visible");
		Group deleted = createGroup(owner.id(), "Deleted");
		Group disabledTenantGroup = createGroup(disabled.id(), "Disabled Tenant");
		this.groups.delete(owner.id(), deleted.id(), deleted.version());
		this.tenants.disable(disabled.id());

		String missing = responseBody(owner.id(), UUID.randomUUID().toString());
		String malformed = responseBody(owner.id(), "not-a-uuid");
		String nonCanonical = responseBody(owner.id(), visible.id().toString().toUpperCase(Locale.ROOT));
		String crossTenant = responseBody(other.id(), visible.id().toString());
		String deletedBody = responseBody(owner.id(), deleted.id().toString());
		String disabledTenantBody = responseBody(disabled.id(), disabledTenantGroup.id().toString());
		assertThat(List.of(malformed, nonCanonical, crossTenant, deletedBody, disabledTenantBody))
			.containsOnly(missing);
		assertThat(missing).contains(NOT_FOUND_DETAIL).doesNotContain(visible.id().toString());

		this.mockMvc.perform(get("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(owner.id(), "scim.write")))
			.accept(SCIM_JSON))
			.andExpect(status().isForbidden())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
					"Bearer error=\"insufficient_scope\", scope=\"scim.read\""));
	}

	private String responseBody(TenantId tenantId, String groupId) throws Exception {
		MvcResult result = this.mockMvc.perform(get("/scim/v2/Groups/{id}", groupId)
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

	private String invalidMemberResponse(TenantId tenantId, String request) throws Exception {
		MvcResult result = this.mockMvc.perform(post("/scim/v2/Groups")
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenantId, "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("400"))
			.andExpect(jsonPath("$.scimType").value("invalidValue"))
			.andReturn();
		return result.getResponse().getContentAsString();
	}

	private long groupCount(TenantId tenantId) {
		return this.jdbcClient.sql("SELECT COUNT(*) FROM groups WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(Long.class)
			.single();
	}

	private long membershipCount(TenantId tenantId) {
		return this.jdbcClient.sql("SELECT COUNT(*) FROM group_memberships WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.query(Long.class)
			.single();
	}

	private static String memberRequest(UserId userId) {
		return """
				{
				  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
				  "displayName":"Unavailable Member",
				  "members":[{"value":"%s"}]
				}
				""".formatted(userId);
	}

	private Tenant createTenant() {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("scim-group-" + suffix, "SCIM Group Test"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private Group createGroup(TenantId tenantId, String displayName) {
		return this.groups.create(tenantId, new CreateGroupRequest(displayName));
	}

	private User createUser(TenantId tenantId, String username) {
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username))));
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
