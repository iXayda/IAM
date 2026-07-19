package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.group.Group;
import com.ixayda.iam.group.GroupId;
import com.ixayda.iam.group.GroupMembership;
import com.ixayda.iam.group.GroupStatus;
import com.ixayda.iam.group.ReplaceGroupRequest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimGroupPatchRequestTests {

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final TenantId TENANT_ID =
			new TenantId(UUID.fromString("00000000-0000-0000-0000-000000000010"));

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("00000000-0000-0000-0000-000000000020"));

	private static final UserId FIRST_USER_ID =
			new UserId(UUID.fromString("00000000-0000-0000-0000-000000000101"));

	private static final UserId SECOND_USER_ID =
			new UserId(UUID.fromString("00000000-0000-0000-0000-000000000102"));

	private static final UserId THIRD_USER_ID =
			new UserId(UUID.fromString("00000000-0000-0000-0000-000000000103"));

	private static final ScimProperties PROPERTIES =
			new ScimProperties(URI.create("https://iam.example.test/scim/v2"));

	private final ScimJsonCodec codec = new ScimJsonCodec();

	private final ScimGroupMapper mapper = new ScimGroupMapper(PROPERTIES);

	@Test
	void appliesOrderedProfileAndMembershipOperations() throws Exception {
		ScimGroupPatchRequest request = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[
				   {"op":"add","path":"MEMBERS","value":{"VALUE":"%s"}},
				   {"op":"remove","path":"members[value eq \\\"%s\\\"]"},
				   {"op":"replace","path":"displayName","value":" Platform "}
				 ]}
				""".formatted(THIRD_USER_ID, SECOND_USER_ID));

		ReplaceGroupRequest replacement = request.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);

		assertThat(replacement.displayName()).isEqualTo("Platform");
		assertThat(replacement.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, THIRD_USER_ID);
	}

	@Test
	void supportsPathlessAddsAndReplacements() throws Exception {
		ScimGroupPatchRequest add = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"add","value":{"DisplayName":"Platform","Members":[{"Value":"%s"}]}}]}
				""".formatted(THIRD_USER_ID));
		ReplaceGroupRequest added = add.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper, this.codec,
				PROPERTIES);
		assertThat(added.displayName()).isEqualTo("Platform");
		assertThat(added.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, SECOND_USER_ID, THIRD_USER_ID);

		ScimGroupPatchRequest replace = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"replace","value":{"Members":[{"Value":"%s"}]}}]}
				""".formatted(THIRD_USER_ID));
		ReplaceGroupRequest replaced = replace.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);
		assertThat(replaced.displayName()).isEqualTo("Engineering");
		assertThat(replaced.memberIds()).containsExactly(THIRD_USER_ID);
	}

	@Test
	void treatsDuplicateAddsAndMissingMemberRemovalsAsNoOps() throws Exception {
		ScimGroupPatchRequest request = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[
				   {"op":"add","path":"members","value":[{"value":"%s"}]},
				   {"op":"add","path":"members","value":[{"value":"%s"}]},
				   {"op":"remove","path":"members[value eq \\\"%s\\\"]"},
				   {"op":"remove","path":"members[value eq \\\"%s\\\"]"}
				 ]}
				""".formatted(FIRST_USER_ID, THIRD_USER_ID.toString().toUpperCase(Locale.ROOT), THIRD_USER_ID,
				THIRD_USER_ID));

		ReplaceGroupRequest replacement = request.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);

		assertThat(replacement).isEqualTo(
				new ReplaceGroupRequest("Engineering", Set.of(FIRST_USER_ID, SECOND_USER_ID)));
	}

	@Test
	void treatsAddingAnEmptyMemberSetAsANoOpAndReplacingItAsAClear() throws Exception {
		ScimGroupPatchRequest add = parse(patch("add", "members", "[]"));
		ReplaceGroupRequest added = add.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper, this.codec,
				PROPERTIES);
		assertThat(added.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, SECOND_USER_ID);

		ScimGroupPatchRequest replace = parse(patch("replace", "members", "[]"));
		ReplaceGroupRequest replaced = replace.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);
		assertThat(replaced.memberIds()).isEmpty();
		assertApplyError(patch("add", "members", "null"), "invalidValue");
	}

	@Test
	void filteredAddIsIdempotentAndPreservesTheSelectedMemberIdentity() throws Exception {
		ScimGroupPatchRequest request = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"add","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}},
				               {"op":"add","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}}]}
				""".formatted(THIRD_USER_ID, THIRD_USER_ID, THIRD_USER_ID, THIRD_USER_ID));

		ReplaceGroupRequest replacement = request.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);

		assertThat(replacement.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, SECOND_USER_ID, THIRD_USER_ID);

		assertParseError("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"add","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}}]}
				""".formatted(FIRST_USER_ID, THIRD_USER_ID), "mutability");
	}

	@Test
	void reportsFilteredReplaceWithoutAMatchAsNoTarget() throws Exception {
		String request = """
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"replace","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}}]}
				""".formatted(THIRD_USER_ID, SECOND_USER_ID);

		assertApplyError(request, "noTarget");
	}

	@Test
	void filteredReplacePreservesTheSelectedMemberIdentity() throws Exception {
		ScimGroupPatchRequest noOp = parse("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"replace","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}}]}
				""".formatted(FIRST_USER_ID, FIRST_USER_ID));

		ReplaceGroupRequest unchanged = noOp.apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES);
		assertThat(unchanged.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, SECOND_USER_ID);

		assertApplyError("""
				{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				 "Operations":[{"op":"replace","path":"members[value eq \\\"%s\\\"]",
				                "value":{"value":"%s"}}]}
				""".formatted(FIRST_USER_ID, THIRD_USER_ID), "mutability");
	}

	@Test
	void rejectsInvalidStructurePathsFiltersMutabilityAndValues() {
		assertParseError("{}", "invalidSyntax");
		assertParseError(patch("change", "displayName", "\"secret\""), "invalidSyntax");
		assertParseError(patch("replace", "unknownSecret", "\"secret\""), "invalidPath");
		assertParseError(patch("replace", "id", "\"secret\""), "mutability");
		assertParseError(remove("displayName"), "mutability");
		assertParseError(patch("replace", "members.value", "\"" + FIRST_USER_ID + "\""), "mutability");
		assertParseError(remove("members[type eq \"User\"]"), "invalidFilter");
		assertParseError(remove("members[value co \"secret\"]"), "invalidFilter");
		assertApplyError(patch("add", "members", "[{\"value\":\"not-a-uuid\"}]"), "invalidValue");
		assertApplyError(patch("replace", "members[value eq \"" + FIRST_USER_ID + "\"]",
				"{\"value\":\"" + THIRD_USER_ID + "\"}"), "mutability");
		assertApplyError(patch("replace", "displayName", "null"), "mutability");
	}

	@Test
	void boundsOperationAndJsonComplexityWithoutReflectingInput() {
		String operations = java.util.stream.IntStream.rangeClosed(0, 100)
			.mapToObj((ignored) -> "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"secret\"}")
			.collect(java.util.stream.Collectors.joining(","));
		assertParseError("{\"schemas\":[\"" + ScimGroupPatchRequest.SCHEMA_URN
				+ "\"],\"Operations\":[" + operations + "]}", "tooMany");
	}

	@Test
	void acceptsOneThousandDistinctMembersAndRejectsTheNextOne() throws Exception {
		ObjectNode source = this.codec.jsonMapper().createObjectNode();
		source.putArray("schemas").add(ScimGroupPatchRequest.SCHEMA_URN);
		ObjectNode operation = source.putArray("Operations").addObject();
		operation.put("op", "replace").put("path", "members");
		var members = operation.putArray("value");
		java.util.stream.LongStream.rangeClosed(1, 1_000)
			.forEach((value) -> members.addObject().put("value", new UUID(0, value).toString()));

		ReplaceGroupRequest accepted = ScimGroupPatchRequest.parse(source)
			.apply(view(), this.mapper, this.codec, PROPERTIES);
		assertThat(accepted.memberIds()).hasSize(1_000);

		members.addObject().put("value", new UUID(0, 1_001).toString());
		assertThatThrownBy(() -> ScimGroupPatchRequest.parse(source)
			.apply(view(), this.mapper, this.codec, PROPERTIES))
			.isInstanceOfSatisfying(BadRequestException.class,
					(exception) -> assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue"));
	}

	private ScimGroupPatchRequest parse(String request) throws Exception {
		return ScimGroupPatchRequest.parse((ObjectNode) this.codec.jsonMapper().readTree(request));
	}

	private void assertParseError(String request, String scimType) {
		assertThatThrownBy(() -> parse(request))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo(scimType);
				assertThat(exception.getMessage()).doesNotContain("secret");
			});
	}

	private void assertApplyError(String request, String scimType) {
		assertThatThrownBy(() -> parse(request).apply(view(FIRST_USER_ID, SECOND_USER_ID), this.mapper,
				this.codec, PROPERTIES))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo(scimType);
				assertThat(exception.getMessage()).doesNotContain("secret", THIRD_USER_ID.toString());
			});
	}

	private static ScimGroupView view(UserId... members) {
		Group group = new Group(GROUP_ID, TENANT_ID, "Engineering", GroupStatus.ACTIVE, 4, CREATED_AT,
				CREATED_AT.plusSeconds(4));
		Set<GroupMembership> memberships = java.util.Arrays.stream(members)
			.map((member) -> new GroupMembership(TENANT_ID, GROUP_ID, member, CREATED_AT))
			.collect(java.util.stream.Collectors.toUnmodifiableSet());
		return new ScimGroupView(group, memberships);
	}

	private static String patch(String op, String path, String value) {
		return "{\"schemas\":[\"" + ScimGroupPatchRequest.SCHEMA_URN + "\"],\"Operations\":[{\"op\":\""
				+ op + "\",\"path\":\"" + path.replace("\"", "\\\"") + "\",\"value\":" + value + "}]}";
	}

	private static String remove(String path) {
		return "{\"schemas\":[\"" + ScimGroupPatchRequest.SCHEMA_URN
				+ "\"],\"Operations\":[{\"op\":\"remove\",\"path\":\""
				+ path.replace("\"", "\\\"") + "\"}]}";
	}

}
