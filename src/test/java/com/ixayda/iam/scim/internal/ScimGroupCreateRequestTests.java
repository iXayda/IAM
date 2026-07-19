package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.group.CreateGroupRequest;
import com.ixayda.iam.group.GroupOperations;
import com.ixayda.iam.group.ReplaceGroupRequest;
import com.ixayda.iam.user.UserId;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.types.Meta;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimGroupCreateRequestTests {

	private static final ScimProperties PROPERTIES =
			new ScimProperties(URI.create("https://iam.example.test/scim/v2"));

	private static final UserId FIRST_USER_ID =
			new UserId(UUID.fromString("00000000-0000-0000-0000-000000000101"));

	private static final UserId SECOND_USER_ID =
			new UserId(UUID.fromString("00000000-0000-0000-0000-000000000102"));

	@Test
	void mapsDirectUsersAndDeduplicatesNormalizedMemberValues() throws Exception {
		ScimGroupCreateResource resource = resource();
		resource.setDisplayName(" Engineering ").setMembers(List.of(
				new Member().setValue(FIRST_USER_ID.toString().toUpperCase()).setType("user")
					.setRef(URI.create("Users/" + FIRST_USER_ID)),
				new Member().setValue(FIRST_USER_ID.toString())
					.setRef(PROPERTIES.endpoint(ScimUserController.USERS_PATH, FIRST_USER_ID.toString())),
				new Member().setValue(SECOND_USER_ID.toString())
					.setRef(URI.create("/scim/v2/Users/" + SECOND_USER_ID))));
		resource.setId("client-controlled-id");
		resource.setMeta(new Meta().setLocation(URI.create("https://attacker.example.test/Groups/1")));

		ScimGroupCreateRequest parsed = ScimGroupCreateRequest.parse(resource, PROPERTIES);

		assertThat(parsed.request()).isEqualTo(new CreateGroupRequest("Engineering"));
		assertThat(parsed.memberIds()).containsExactlyInAnyOrder(FIRST_USER_ID, SECOND_USER_ID);
		assertThat(parsed.replacement()).isEqualTo(
				new ReplaceGroupRequest("Engineering", Set.of(FIRST_USER_ID, SECOND_USER_ID)));
	}

	@Test
	void normalizesCaseInsensitiveJsonAttributesAndIgnoresReadOnlyValues() throws Exception {
		ScimJsonCodec codec = new ScimJsonCodec();
		ObjectNode source = codec.jsonMapper().createObjectNode();
		source.putArray("SCHEMAS").add(ScimGroupSchema.URN);
		source.put("DISPLAYNAME", "Platform");
		source.put("ID", 42);
		source.put("META", "ignored");
		source.putArray("MEMBERS").addObject()
			.put("VALUE", FIRST_USER_ID.toString().toUpperCase())
			.put("TYPE", "USER")
			.put("$REF", "Users/" + FIRST_USER_ID);

		ScimGroupCreateRequest parsed = ScimGroupCreateRequest.parse(source, codec, PROPERTIES);

		assertThat(parsed.request()).isEqualTo(new CreateGroupRequest("Platform"));
		assertThat(parsed.memberIds()).containsExactly(FIRST_USER_ID);
	}

	@Test
	void rejectsMissingUnsupportedAndInconsistentValuesWithoutReflectingThem() {
		assertInvalid(resource());
		ScimGroupCreateResource wrongSchema = resource();
		wrongSchema.setDisplayName("Engineering");
		wrongSchema.setSchemaUrns(Set.of("urn:example:unsupported:Group"));
		assertInvalid(wrongSchema);
		ScimGroupCreateResource externalId = resource();
		externalId.setDisplayName("Engineering").setExternalId("secret-external-id");
		assertInvalid(externalId);
		assertInvalid(member(new Member()));
		assertInvalid(member(new Member().setValue(FIRST_USER_ID.toString()).setType("Group")));
		assertInvalid(member(new Member().setValue(FIRST_USER_ID.toString()).setDisplay("secret-display")));
		assertInvalid(member(new Member().setValue(FIRST_USER_ID.toString())
			.setRef(URI.create("https://external.example.test/scim/v2/Users/" + FIRST_USER_ID))));
		assertInvalid(member(new Member().setValue(FIRST_USER_ID.toString())
			.setRef(URI.create("Users/" + SECOND_USER_ID))));
		assertInvalid(member(new Member().setValue(FIRST_USER_ID.toString())
			.setRef(URI.create("Users/" + FIRST_USER_ID + "?secret=query"))));
	}

	@Test
	void rejectsUnknownJsonAttributesAndDistinctMemberOverflow() {
		ScimJsonCodec codec = new ScimJsonCodec();
		ObjectNode unknown = validSource(codec);
		unknown.put("secretUnknown", "secret-value");
		assertInvalid(unknown, codec);
		ScimGroupCreateResource overflow = resource();
		overflow.setDisplayName("Large").setMembers(java.util.stream.IntStream
			.rangeClosed(0, GroupOperations.MAX_MEMBERS_PER_GROUP)
			.mapToObj((value) -> new Member().setValue(new UUID(0, value + 1L).toString()))
			.toList());
		assertInvalid(overflow);
	}

	private static ScimGroupCreateResource resource() {
		ScimGroupCreateResource resource = new ScimGroupCreateResource();
		resource.setSchemaUrns(Set.of(ScimGroupSchema.URN));
		return resource;
	}

	private static ScimGroupCreateResource member(Member member) {
		ScimGroupCreateResource resource = resource();
		resource.setDisplayName("Engineering").setMembers(List.of(member));
		return resource;
	}

	private static ObjectNode validSource(ScimJsonCodec codec) {
		ObjectNode source = codec.jsonMapper().createObjectNode();
		source.putArray("schemas").add(ScimGroupSchema.URN);
		source.put("displayName", "Engineering");
		return source;
	}

	private static void assertInvalid(ScimGroupCreateResource resource) {
		assertThatThrownBy(() -> ScimGroupCreateRequest.parse(resource, PROPERTIES))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
				assertThat(exception.getMessage()).doesNotContain("secret");
			});
	}

	private static void assertInvalid(ObjectNode source, ScimJsonCodec codec) {
		assertThatThrownBy(() -> ScimGroupCreateRequest.parse(source, codec, PROPERTIES))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
				assertThat(exception.getMessage()).doesNotContain("secret");
			});
	}

}
