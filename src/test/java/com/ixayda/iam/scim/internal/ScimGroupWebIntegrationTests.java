package com.ixayda.iam.scim.internal;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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

	@Autowired
	private PlatformTransactionManager transactionManager;

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
	void replacesAGroupAndItsMembersWithOneDirectoryRevision() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User removed = createUser(tenant.id(), "replace-removed");
		User retained = createUser(tenant.id(), "replace-retained");
		User disabled = createUser(tenant.id(), "replace-disabled");
		User locked = createUser(tenant.id(), "replace-locked");
		this.users.disable(tenant.id(), disabled.id());
		this.users.lock(tenant.id(), locked.id());
		Group created = createGroup(tenant.id(), "Engineering");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(),
				Set.of(removed.id(), retained.id()));
		long removedVersion = userVersion(tenant.id(), removed.id());
		long retainedVersion = userVersion(tenant.id(), retained.id());
		long disabledVersion = userVersion(tenant.id(), disabled.id());
		long lockedVersion = userVersion(tenant.id(), locked.id());
		String location = "https://scim.example.test/scim/v2/Groups/" + current.id();
		String request = """
				{
				  "schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],
				  "id":"00000000-0000-0000-0000-000000000999",
				  "meta":42,
				  "displayName":"Platform Operators",
				  "members":[
				    {"value":"%s","type":"user","$ref":"Users/%s"},
				    {"value":"%s","$ref":"/scim/v2/Users/%s"},
				    {"value":"%s"},
				    {"value":"%s"}
				  ]
				}
				""".formatted(retained.id().toString().toUpperCase(Locale.ROOT), retained.id(),
				disabled.id(), disabled.id(), locked.id(), retained.id());

		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("tenant_id", other.id().toString())
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(current.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Platform Operators"))
			.andExpect(jsonPath("$.members", hasSize(3)))
			.andExpect(jsonPath("$.members[*].value", containsInAnyOrder(retained.id().toString(),
					disabled.id().toString(), locked.id().toString())))
			.andExpect(jsonPath("$.members[*].type", containsInAnyOrder("User", "User", "User")))
			.andExpect(jsonPath("$.meta.location").value(location))
			.andExpect(jsonPath("$.meta.version").doesNotExist());

		Group stored = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(stored.displayName()).isEqualTo("Platform Operators");
		assertThat(stored.version()).isEqualTo(current.version() + 1);
		assertThat(this.groups.findMembers(tenant.id(), current.id())).extracting(GroupMembership::userId)
			.containsExactlyInAnyOrder(retained.id(), disabled.id(), locked.id());
		assertThat(userVersion(tenant.id(), removed.id())).isEqualTo(removedVersion + 1);
		assertThat(userVersion(tenant.id(), retained.id())).isEqualTo(retainedVersion);
		assertThat(userVersion(tenant.id(), disabled.id())).isEqualTo(disabledVersion + 1);
		assertThat(userVersion(tenant.id(), locked.id())).isEqualTo(lockedVersion + 1);
		assertThat(this.groups.findById(other.id(), current.id())).isEmpty();
	}

	@Test
	void patchesAGroupAndItsMembersAtomicallyWithOneDirectoryRevision() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User removed = createUser(tenant.id(), "patch-removed");
		User retained = createUser(tenant.id(), "patch-retained");
		User added = createUser(tenant.id(), "patch-added");
		Group created = createGroup(tenant.id(), "Engineering");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(),
				Set.of(removed.id(), retained.id()));
		long removedVersion = userVersion(tenant.id(), removed.id());
		long retainedVersion = userVersion(tenant.id(), retained.id());
		long addedVersion = userVersion(tenant.id(), added.id());
		String location = "https://scim.example.test/scim/v2/Groups/" + current.id();
		String request = """
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[
				   {"op":"replace","path":"displayName","value":"Platform Operators"},
				   {"op":"remove","path":"members[value eq \\\"%s\\\"]"},
				   {"op":"add","path":"members","value":[
				      {"value":"%s"},{"value":"%s","type":"user","$ref":"Users/%s"}]},
				   {"op":"remove","path":"members[value eq \\\"00000000-0000-0000-0000-000000000999\\\"]"}
				 ]}
				""".formatted(removed.id(), retained.id(), added.id(), added.id());

		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("tenant_id", other.id().toString())
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(current.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Platform Operators"))
			.andExpect(jsonPath("$.members", hasSize(2)))
			.andExpect(jsonPath("$.members[*].value",
					containsInAnyOrder(retained.id().toString(), added.id().toString())))
			.andExpect(jsonPath("$.members[*].type", containsInAnyOrder("User", "User")))
			.andExpect(jsonPath("$.meta.location").value(location))
			.andExpect(jsonPath("$.meta.version").doesNotExist());

		Group stored = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(stored.displayName()).isEqualTo("Platform Operators");
		assertThat(stored.version()).isEqualTo(current.version() + 1);
		assertThat(this.groups.findMembers(tenant.id(), current.id())).extracting(GroupMembership::userId)
			.containsExactlyInAnyOrder(retained.id(), added.id());
		assertThat(userVersion(tenant.id(), removed.id())).isEqualTo(removedVersion + 1);
		assertThat(userVersion(tenant.id(), retained.id())).isEqualTo(retainedVersion);
		assertThat(userVersion(tenant.id(), added.id())).isEqualTo(addedVersion + 1);
		assertThat(this.groups.findById(other.id(), current.id())).isEmpty();
	}

	@Test
	void preservesNoOpPatchesAndRollsBackInvalidMembersAndNoTargets() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User member = createUser(tenant.id(), "patch-noop-member");
		User replacement = createUser(tenant.id(), "patch-no-target-replacement");
		User crossTenant = createUser(other.id(), "patch-cross-tenant");
		User deleted = createUser(tenant.id(), "patch-deleted");
		this.users.delete(tenant.id(), deleted.id());
		Group created = createGroup(tenant.id(), "Engineering");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(), Set.of(member.id()));
		long memberVersion = userVersion(tenant.id(), member.id());
		String authorization = bearer(token(tenant.id(), "scim.write"));

		String noOp = """
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[
				   {"op":"add","path":"members","value":{"value":"%s"}},
				   {"op":"remove","path":"members[value eq \\\"00000000-0000-0000-0000-000000000999\\\"]"}
				 ]}
				""".formatted(member.id());
		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(noOp))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.displayName").value("Engineering"))
			.andExpect(jsonPath("$.members[0].value").value(member.id().toString()));
		assertThat(this.groups.findById(tenant.id(), current.id())).contains(current);
		assertThat(userVersion(tenant.id(), member.id())).isEqualTo(memberVersion);

		UserId missing = new UserId(new UUID(Long.MAX_VALUE, Long.MAX_VALUE));
		String invalidMember = """
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[
				   {"op":"replace","path":"displayName","value":"Must Not Persist"},
				   {"op":"add","path":"members","value":{"value":"%s"}}
				 ]}
				""".formatted(missing);
		String invalidBody = invalidPatchMemberBody(tenant.id(), current.id().toString(), invalidMember);
		assertThat(invalidBody).doesNotContain("Must Not Persist", missing.toString());
		String crossTenantBody = invalidPatchMemberBody(tenant.id(), current.id().toString(),
				groupPatch("add", "members", "[{\"value\":\"" + crossTenant.id() + "\"}]"));
		String deletedBody = invalidPatchMemberBody(tenant.id(), current.id().toString(),
				groupPatch("add", "members", "[{\"value\":\"" + deleted.id() + "\"}]"));
		assertThat(List.of(crossTenantBody, deletedBody)).containsOnly(invalidBody);
		assertThat(crossTenantBody).doesNotContain(crossTenant.id().toString(), deleted.id().toString());
		assertThat(this.groups.findById(tenant.id(), current.id())).contains(current);
		assertThat(this.groups.findMembers(tenant.id(), current.id())).extracting(GroupMembership::userId)
			.containsExactly(member.id());
		assertThat(userVersion(tenant.id(), member.id())).isEqualTo(memberVersion);

		String noTarget = """
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"replace",
				   "path":"members[value eq \\\"00000000-0000-0000-0000-000000000999\\\"]",
				   "value":{"value":"%s"}}]}
				""".formatted(replacement.id());
		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(noTarget))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("noTarget"))
			.andExpect(content().string(not(containsString(replacement.id().toString()))));
		assertThat(this.groups.findById(tenant.id(), current.id())).contains(current);
	}

	@Test
	void validatesPatchVisibilityPreconditionsScopeProjectionAndSyntax() throws Exception {
		Tenant owner = createTenant();
		Tenant other = createTenant();
		Tenant disabled = createTenant();
		Group visible = createGroup(owner.id(), "Visible");
		Group deleted = createGroup(owner.id(), "Deleted");
		Group disabledGroup = createGroup(disabled.id(), "Disabled");
		this.groups.delete(owner.id(), deleted.id(), deleted.version());
		this.tenants.disable(disabled.id());
		String request = groupPatch("replace", "displayName", "\"Patched\"");
		String authorization = bearer(token(owner.id(), "scim.write"));

		String missing = patchNotFoundBody(owner.id(), UUID.randomUUID().toString(), request);
		String malformed = patchNotFoundBody(owner.id(), "not-a-uuid", request);
		String nonCanonical = patchNotFoundBody(owner.id(),
				visible.id().toString().toUpperCase(Locale.ROOT), request);
		String crossTenant = patchNotFoundBody(other.id(), visible.id().toString(), request);
		String deletedBody = patchNotFoundBody(owner.id(), deleted.id().toString(), request);
		String disabledBody = patchNotFoundBody(disabled.id(), disabledGroup.id().toString(), request);
		assertThat(List.of(malformed, nonCanonical, crossTenant, deletedBody, disabledBody)).containsOnly(missing);
		assertThat(missing).contains(NOT_FOUND_DETAIL).doesNotContain(visible.id().toString());

		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.header(HttpHeaders.IF_MATCH, "*")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));
		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(owner.id(), "scim.read")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content("{\"schemas\":[\"" + ScimGroupPatchRequest.SCHEMA_URN
					+ "\"],\"Operations\":[{\"op\":\"replace\",\"op\":\"add\"}]}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidSyntax"));
		assertThat(this.groups.findById(owner.id(), visible.id())).contains(visible);

		String location = "https://scim.example.test/scim/v2/Groups/" + visible.id();
		this.mockMvc.perform(patch("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "displayName")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(visible.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Patched"))
			.andExpect(jsonPath("$.members").doesNotExist())
			.andExpect(jsonPath("$.meta").doesNotExist());
	}

	@Test
	void mapsConcurrentGroupPatchesToOneSuccessAndOneConflict() throws Exception {
		Tenant tenant = createTenant();
		Group current = createGroup(tenant.id(), "Concurrent Patch");
		String authorization = bearer(token(tenant.id(), "scim.write"));
		CountDownLatch rowLocked = new CountDownLatch(1);
		CountDownLatch releaseRow = new CountDownLatch(1);
		List<MvcResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(3)) {
			Future<?> locker = executor.submit(() -> transactionTemplate().executeWithoutResult(status -> {
				this.jdbcClient.sql("""
						SELECT group_id
						FROM groups
						WHERE tenant_id = :tenantId AND group_id = :groupId
						FOR UPDATE
						""")
					.param("tenantId", tenant.id().value())
					.param("groupId", current.id().value())
					.query(UUID.class)
					.single();
				rowLocked.countDown();
				await(releaseRow);
			}));

			assertThat(rowLocked.await(5, TimeUnit.SECONDS)).isTrue();
			Future<MvcResult> firstRequest = executor.submit(() -> patchGroup(current, "First Patch", authorization));
			Future<MvcResult> secondRequest = executor.submit(() -> patchGroup(current, "Second Patch", authorization));
			try {
				assertThat(waitUntilGroupWritesBlocked(2)).isTrue();
			}
			finally {
				releaseRow.countDown();
			}
			locker.get(5, TimeUnit.SECONDS);
			results.add(firstRequest.get(10, TimeUnit.SECONDS));
			results.add(secondRequest.get(10, TimeUnit.SECONDS));
		}

		assertThat(results).extracting(result -> result.getResponse().getStatus())
			.containsExactlyInAnyOrder(200, 409);
		MvcResult rejected = results.stream()
			.filter(result -> result.getResponse().getStatus() == 409)
			.findFirst()
			.orElseThrow();
		String rejectedBody = rejected.getResponse().getContentAsString();
		assertThat(JSON.readTree(rejectedBody).get("status").stringValue()).isEqualTo("409");
		assertThat(rejectedBody).doesNotContain(current.id().toString(), "First Patch", "Second Patch");
		Group stored = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(stored.version()).isEqualTo(current.version() + 1);
		assertThat(stored.displayName()).isIn("First Patch", "Second Patch");
	}

	@Test
	void deletesATenantScopedGroupAndItsMembershipsWithAnEmptyResponse() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User first = createUser(tenant.id(), "delete-group-first");
		User second = createUser(tenant.id(), "delete-group-second");
		Group created = createGroup(tenant.id(), "Delete Group");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(),
				Set.of(first.id(), second.id()));
		long firstVersion = userVersion(tenant.id(), first.id());
		long secondVersion = userVersion(tenant.id(), second.id());

		this.mockMvc.perform(delete("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.write")))
			.queryParam("tenant_id", other.id().toString())
			.accept(SCIM_JSON))
			.andExpect(status().isNoContent())
			.andExpect(content().string(""))
			.andExpect(header().doesNotExist(HttpHeaders.CONTENT_TYPE))
			.andExpect(header().doesNotExist(HttpHeaders.LOCATION))
			.andExpect(header().doesNotExist(HttpHeaders.CONTENT_LOCATION))
			.andExpect(header().doesNotExist(HttpHeaders.ETAG));

		assertThat(this.groups.findById(tenant.id(), current.id())).isEmpty();
		assertThat(storedGroupStatus(tenant.id(), current.id())).isEqualTo("deleted");
		assertThat(storedGroupVersion(tenant.id(), current.id())).isEqualTo(current.version() + 1);
		assertThat(groupMembershipCount(tenant.id(), current.id())).isZero();
		assertThat(userVersion(tenant.id(), first.id())).isEqualTo(firstVersion + 1);
		assertThat(userVersion(tenant.id(), second.id())).isEqualTo(secondVersion + 1);
		this.mockMvc.perform(get("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.accept(SCIM_JSON))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL));
		assertThat(deleteNotFoundBody(tenant.id(), current.id().toString())).contains(NOT_FOUND_DETAIL);
	}

	@Test
	void rejectsInvisibleConditionalAndReadOnlyGroupDeletesWithoutChangingData() throws Exception {
		Tenant owner = createTenant();
		Tenant other = createTenant();
		Tenant disabled = createTenant();
		Group visible = createGroup(owner.id(), "Visible");
		Group deleted = createGroup(owner.id(), "Deleted");
		Group disabledGroup = createGroup(disabled.id(), "Disabled");
		this.groups.delete(owner.id(), deleted.id(), deleted.version());
		this.tenants.disable(disabled.id());

		this.mockMvc.perform(delete("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(owner.id(), "scim.write")))
			.header(HttpHeaders.IF_MATCH, "*")
			.accept(SCIM_JSON))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));
		this.mockMvc.perform(delete("/scim/v2/Groups/{id}", visible.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(owner.id(), "scim.read")))
			.accept(SCIM_JSON))
			.andExpect(status().isForbidden());

		String missing = deleteNotFoundBody(owner.id(), UUID.randomUUID().toString());
		String malformed = deleteNotFoundBody(owner.id(), "not-a-uuid");
		String nonCanonical = deleteNotFoundBody(owner.id(),
				visible.id().toString().toUpperCase(Locale.ROOT));
		String crossTenant = deleteNotFoundBody(other.id(), visible.id().toString());
		String alreadyDeleted = deleteNotFoundBody(owner.id(), deleted.id().toString());
		String disabledBody = deleteNotFoundBody(disabled.id(), disabledGroup.id().toString());
		assertThat(List.of(malformed, nonCanonical, crossTenant, alreadyDeleted, disabledBody)).containsOnly(missing);
		assertThat(missing).contains(NOT_FOUND_DETAIL).doesNotContain(visible.id().toString());
		assertThat(this.groups.findById(owner.id(), visible.id())).contains(visible);
	}

	@Test
	void commitsOnlyOneOfTwoConcurrentGroupDeletes() throws Exception {
		Tenant tenant = createTenant();
		User member = createUser(tenant.id(), "concurrent-delete-member");
		Group created = createGroup(tenant.id(), "Concurrent Delete");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(), Set.of(member.id()));
		long memberVersion = userVersion(tenant.id(), member.id());
		String authorization = bearer(token(tenant.id(), "scim.write"));
		CountDownLatch rowLocked = new CountDownLatch(1);
		CountDownLatch releaseRow = new CountDownLatch(1);
		List<MvcResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(3)) {
			Future<?> locker = executor.submit(() -> transactionTemplate().executeWithoutResult(status -> {
				this.jdbcClient.sql("""
						SELECT group_id
						FROM groups
						WHERE tenant_id = :tenantId AND group_id = :groupId
						FOR UPDATE
						""")
					.param("tenantId", tenant.id().value())
					.param("groupId", current.id().value())
					.query(UUID.class)
					.single();
				rowLocked.countDown();
				await(releaseRow);
			}));

			assertThat(rowLocked.await(5, TimeUnit.SECONDS)).isTrue();
			Future<MvcResult> first = executor.submit(() -> deleteGroup(current, authorization));
			Future<MvcResult> second = executor.submit(() -> deleteGroup(current, authorization));
			try {
				assertThat(waitUntilGroupWritesBlocked(2)).isTrue();
			}
			finally {
				releaseRow.countDown();
			}
			locker.get(5, TimeUnit.SECONDS);
			results.add(first.get(10, TimeUnit.SECONDS));
			results.add(second.get(10, TimeUnit.SECONDS));
		}

		assertThat(results).extracting(result -> result.getResponse().getStatus())
			.containsExactlyInAnyOrder(204, 404);
		MvcResult rejected = results.stream()
			.filter(result -> result.getResponse().getStatus() == 404)
			.findFirst()
			.orElseThrow();
		assertThat(rejected.getResponse().getContentAsString())
			.contains(NOT_FOUND_DETAIL)
			.doesNotContain(current.id().toString());
		assertThat(storedGroupVersion(tenant.id(), current.id())).isEqualTo(current.version() + 1);
		assertThat(groupMembershipCount(tenant.id(), current.id())).isZero();
		assertThat(userVersion(tenant.id(), member.id())).isEqualTo(memberVersion + 1);
	}

	@Test
	void clearsOmittedNullAndEmptyReplacementMembersWithoutAdvancingNoOps() throws Exception {
		Tenant tenant = createTenant();
		User member = createUser(tenant.id(), "replace-clear-member");
		Group created = createGroup(tenant.id(), "Engineering");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(), Set.of(member.id()));
		long memberVersion = userVersion(tenant.id(), member.id());
		String authorization = bearer(token(tenant.id(), "scim.write"));

		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(groupReplacement("Engineering", null)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.members", hasSize(0)));
		Group cleared = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(cleared.version()).isEqualTo(current.version() + 1);
		assertThat(this.groups.findMembers(tenant.id(), current.id())).isEmpty();
		assertThat(userVersion(tenant.id(), member.id())).isEqualTo(memberVersion + 1);

		String explicitNull = "{\"schemas\":[\"" + ScimGroupSchema.URN
				+ "\"],\"displayName\":\"Engineering\",\"members\":null}";
		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(explicitNull))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.members", hasSize(0)));
		assertThat(this.groups.findById(tenant.id(), current.id())).contains(cleared);

		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(groupReplacement("Platform", "[]")))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.displayName").value("Platform"))
			.andExpect(jsonPath("$.members", hasSize(0)));
		assertThat(this.groups.findById(tenant.id(), current.id()).orElseThrow().version())
			.isEqualTo(cleared.version() + 1);
	}

	@Test
	void mapsConcurrentFullReplacementsToOneSuccessAndOneConflict() throws Exception {
		Tenant tenant = createTenant();
		Group current = createGroup(tenant.id(), "Concurrent Replacement");
		User first = createUser(tenant.id(), "concurrent-replace-first");
		User second = createUser(tenant.id(), "concurrent-replace-second");
		String authorization = bearer(token(tenant.id(), "scim.write"));
		CountDownLatch rowLocked = new CountDownLatch(1);
		CountDownLatch releaseRow = new CountDownLatch(1);
		List<MvcResult> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(3)) {
			Future<?> locker = executor.submit(() -> transactionTemplate().executeWithoutResult(status -> {
				this.jdbcClient.sql("""
						SELECT group_id
						FROM groups
						WHERE tenant_id = :tenantId AND group_id = :groupId
						FOR UPDATE
						""")
					.param("tenantId", tenant.id().value())
					.param("groupId", current.id().value())
					.query(UUID.class)
					.single();
				rowLocked.countDown();
				await(releaseRow);
			}));

			assertThat(rowLocked.await(5, TimeUnit.SECONDS)).isTrue();
			Future<MvcResult> firstRequest = executor.submit(() -> replaceGroup(current, "First Replacement",
					first.id(), authorization));
			Future<MvcResult> secondRequest = executor.submit(() -> replaceGroup(current, "Second Replacement",
					second.id(), authorization));
			try {
				assertThat(waitUntilGroupWritesBlocked(2)).isTrue();
			}
			finally {
				releaseRow.countDown();
			}
			locker.get(5, TimeUnit.SECONDS);
			results.add(firstRequest.get(10, TimeUnit.SECONDS));
			results.add(secondRequest.get(10, TimeUnit.SECONDS));
		}

		assertThat(results).extracting(result -> result.getResponse().getStatus())
			.containsExactlyInAnyOrder(200, 409);
		MvcResult rejected = results.stream()
			.filter(result -> result.getResponse().getStatus() == 409)
			.findFirst()
			.orElseThrow();
		String rejectedBody = rejected.getResponse().getContentAsString();
		assertThat(JSON.readTree(rejectedBody).get("status").stringValue()).isEqualTo("409");
		assertThat(rejectedBody).doesNotContain(current.id().toString(), first.id().toString(), second.id().toString());

		Group stored = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(stored.version()).isEqualTo(current.version() + 1);
		Set<UserId> storedMembers = this.groups.findMembers(tenant.id(), current.id())
			.stream()
			.map(GroupMembership::userId)
			.collect(java.util.stream.Collectors.toSet());
		if (stored.displayName().equals("First Replacement")) {
			assertThat(storedMembers).containsExactly(first.id());
		}
		else {
			assertThat(stored.displayName()).isEqualTo("Second Replacement");
			assertThat(storedMembers).containsExactly(second.id());
		}
	}

	@Test
	void hidesReplacementTargetsAndNeverUpsertsGroups() throws Exception {
		Tenant owner = createTenant();
		Tenant other = createTenant();
		Tenant disabled = createTenant();
		Group visible = createGroup(owner.id(), "Visible");
		Group deleted = createGroup(owner.id(), "Deleted");
		Group disabledGroup = createGroup(disabled.id(), "Disabled");
		this.groups.delete(owner.id(), deleted.id(), deleted.version());
		this.tenants.disable(disabled.id());
		String request = groupReplacement("Replacement", "[]");
		long ownerGroupCount = groupCount(owner.id());

		String missing = replacementNotFoundBody(owner.id(), UUID.randomUUID().toString(), request);
		String malformed = replacementNotFoundBody(owner.id(), "not-a-uuid", request);
		String nonCanonical = replacementNotFoundBody(owner.id(),
				visible.id().toString().toUpperCase(Locale.ROOT), request);
		String crossTenant = replacementNotFoundBody(other.id(), visible.id().toString(), request);
		String deletedBody = replacementNotFoundBody(owner.id(), deleted.id().toString(), request);
		String disabledBody = replacementNotFoundBody(disabled.id(), disabledGroup.id().toString(), request);

		assertThat(List.of(malformed, nonCanonical, crossTenant, deletedBody, disabledBody)).containsOnly(missing);
		assertThat(missing).contains(NOT_FOUND_DETAIL).doesNotContain(visible.id().toString());
		assertThat(groupCount(owner.id())).isEqualTo(ownerGroupCount);
	}

	@Test
	void rollsBackInvalidReplacementMembersWithoutLeakingAvailability() throws Exception {
		Tenant tenant = createTenant();
		Tenant other = createTenant();
		User removed = createUser(tenant.id(), "replace-rollback-removed");
		User added = createUser(tenant.id(), "replace-rollback-added");
		User crossTenant = createUser(other.id(), "replace-rollback-cross");
		User deleted = createUser(tenant.id(), "replace-rollback-deleted");
		this.users.delete(tenant.id(), deleted.id());
		Group created = createGroup(tenant.id(), "Engineering");
		Group current = this.groups.replaceMembers(tenant.id(), created.id(), created.version(), Set.of(removed.id()));
		long removedVersion = userVersion(tenant.id(), removed.id());
		long addedVersion = userVersion(tenant.id(), added.id());
		UserId missing = new UserId(new UUID(Long.MAX_VALUE, Long.MAX_VALUE));
		String request = groupReplacement("Must Not Persist",
				"[{\"value\":\"" + added.id() + "\"},{\"value\":\"" + missing + "\"}]");

		String missingBody = invalidReplacementMemberBody(tenant.id(), current.id().toString(), request);
		Group unchanged = this.groups.findById(tenant.id(), current.id()).orElseThrow();
		assertThat(unchanged).isEqualTo(current);
		assertThat(this.groups.findMembers(tenant.id(), current.id())).extracting(GroupMembership::userId)
			.containsExactly(removed.id());
		assertThat(userVersion(tenant.id(), removed.id())).isEqualTo(removedVersion);
		assertThat(userVersion(tenant.id(), added.id())).isEqualTo(addedVersion);

		String crossBody = invalidReplacementMemberBody(tenant.id(), current.id().toString(),
				groupReplacement("Secret Cross", "[{\"value\":\"" + crossTenant.id() + "\"}]"));
		String deletedBody = invalidReplacementMemberBody(tenant.id(), current.id().toString(),
				groupReplacement("Secret Deleted", "[{\"value\":\"" + deleted.id() + "\"}]"));
		assertThat(List.of(crossBody, deletedBody)).containsOnly(missingBody);
		assertThat(crossBody).doesNotContain("Secret", crossTenant.id().toString(), deleted.id().toString());
	}

	@Test
	void validatesReplacementPreconditionsProjectionScopeAndDuplicateKeys() throws Exception {
		Tenant tenant = createTenant();
		Group current = createGroup(tenant.id(), "Engineering");
		String request = groupReplacement("Platform", "[]");
		String authorization = bearer(token(tenant.id(), "scim.write"));
		String location = "https://scim.example.test/scim/v2/Groups/" + current.id();

		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.header(HttpHeaders.IF_MATCH, "*")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));
		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "displayName")
			.queryParam("excludedAttributes", "members")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidValue"));
		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenant.id(), "scim.read")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content("{\"schemas\":[\"" + ScimGroupSchema.URN
					+ "\"],\"displayName\":\"First\",\"displayName\":\"Second\"}"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.scimType").value("invalidSyntax"));

		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("attributes", "displayName")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.LOCATION, location))
			.andExpect(header().string(HttpHeaders.CONTENT_LOCATION, location))
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(current.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Platform"))
			.andExpect(jsonPath("$.members").doesNotExist())
			.andExpect(jsonPath("$.meta").doesNotExist());
		this.mockMvc.perform(put("/scim/v2/Groups/{id}", current.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.queryParam("excludedAttributes", "members,meta")
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.schemas[0]").value(ScimGroupSchema.URN))
			.andExpect(jsonPath("$.id").value(current.id().toString()))
			.andExpect(jsonPath("$.displayName").value("Platform"))
			.andExpect(jsonPath("$.members").doesNotExist())
			.andExpect(jsonPath("$.meta").doesNotExist());
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

	private String replacementNotFoundBody(TenantId tenantId, String groupId, String request) throws Exception {
		MvcResult result = this.mockMvc.perform(put("/scim/v2/Groups/{id}", groupId)
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenantId, "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("404"))
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL))
			.andReturn();
		return result.getResponse().getContentAsString();
	}

	private String invalidReplacementMemberBody(TenantId tenantId, String groupId, String request) throws Exception {
		MvcResult result = this.mockMvc.perform(put("/scim/v2/Groups/{id}", groupId)
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

	private String invalidPatchMemberBody(TenantId tenantId, String groupId, String request) throws Exception {
		MvcResult result = this.mockMvc.perform(patch("/scim/v2/Groups/{id}", groupId)
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

	private String patchNotFoundBody(TenantId tenantId, String groupId, String request) throws Exception {
		MvcResult result = this.mockMvc.perform(patch("/scim/v2/Groups/{id}", groupId)
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenantId, "scim.write")))
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(request))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("404"))
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL))
			.andReturn();
		return result.getResponse().getContentAsString();
	}

	private String deleteNotFoundBody(TenantId tenantId, String groupId) throws Exception {
		MvcResult result = this.mockMvc.perform(delete("/scim/v2/Groups/{id}", groupId)
			.header(HttpHeaders.AUTHORIZATION, bearer(token(tenantId, "scim.write")))
			.accept(SCIM_JSON))
			.andExpect(status().isNotFound())
			.andExpect(content().contentTypeCompatibleWith(SCIM_JSON))
			.andExpect(jsonPath("$.schemas[0]").value(ERROR_SCHEMA))
			.andExpect(jsonPath("$.status").value("404"))
			.andExpect(jsonPath("$.detail").value(NOT_FOUND_DETAIL))
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

	private long groupMembershipCount(TenantId tenantId, GroupId groupId) {
		return this.jdbcClient.sql("""
				SELECT COUNT(*)
				FROM group_memberships
				WHERE tenant_id = :tenantId AND group_id = :groupId
				""")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(Long.class)
			.single();
	}

	private long storedGroupVersion(TenantId tenantId, GroupId groupId) {
		return this.jdbcClient.sql("SELECT version FROM groups WHERE tenant_id = :tenantId AND group_id = :groupId")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(Long.class)
			.single();
	}

	private String storedGroupStatus(TenantId tenantId, GroupId groupId) {
		return this.jdbcClient.sql("SELECT status FROM groups WHERE tenant_id = :tenantId AND group_id = :groupId")
			.param("tenantId", tenantId.value())
			.param("groupId", groupId.value())
			.query(String.class)
			.single();
	}

	private long userVersion(TenantId tenantId, UserId userId) {
		return this.users.findById(tenantId, userId).orElseThrow().version();
	}

	private MvcResult replaceGroup(Group group, String displayName, UserId memberId, String authorization)
			throws Exception {
		return this.mockMvc.perform(put("/scim/v2/Groups/{id}", group.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(groupReplacement(displayName, "[{\"value\":\"" + memberId + "\"}]")))
			.andReturn();
	}

	private MvcResult patchGroup(Group group, String displayName, String authorization) throws Exception {
		return this.mockMvc.perform(patch("/scim/v2/Groups/{id}", group.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.contentType(SCIM_JSON)
			.accept(SCIM_JSON)
			.content(groupPatch("replace", "displayName", "\"" + displayName + "\"")))
			.andReturn();
	}

	private MvcResult deleteGroup(Group group, String authorization) throws Exception {
		return this.mockMvc.perform(delete("/scim/v2/Groups/{id}", group.id())
			.header(HttpHeaders.AUTHORIZATION, authorization)
			.accept(SCIM_JSON))
			.andReturn();
	}

	private boolean waitUntilGroupWritesBlocked(long expectedBlockers) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
		do {
			long blockers = this.jdbcClient.sql("""
					SELECT count(*)
					FROM pg_stat_activity
					WHERE wait_event_type = 'Lock'
					  AND cardinality(pg_blocking_pids(pid)) > 0
					  AND query ILIKE '%FROM groups%'
					""")
				.query(Long.class)
				.single();
			if (blockers >= expectedBlockers) {
				return true;
			}
			Thread.sleep(25);
		}
		while (System.nanoTime() < deadline);
		return false;
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

	private static void await(CountDownLatch latch) {
		try {
			if (!latch.await(5, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Timed out waiting to release the group row lock");
			}
		}
		catch (InterruptedException exception) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("Interrupted while waiting to release the group row lock", exception);
		}
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

	private static String groupReplacement(String displayName, String membersJson) {
		String members = membersJson == null ? "" : ",\"members\":" + membersJson;
		return "{\"schemas\":[\"" + ScimGroupSchema.URN + "\"],\"displayName\":\"" + displayName
				+ "\"" + members + "}";
	}

	private static String groupPatch(String op, String path, String value) {
		return "{\"schemas\":[\"" + ScimGroupPatchRequest.SCHEMA_URN + "\"],\"Operations\":[{\"op\":\""
				+ op + "\",\"path\":\"" + path.replace("\"", "\\\"") + "\",\"value\":" + value + "}]}";
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
