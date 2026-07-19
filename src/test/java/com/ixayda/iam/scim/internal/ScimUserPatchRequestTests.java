package com.ixayda.iam.scim.internal;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.ReplaceUserRequest;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ScimUserPatchRequestTests {

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final ScimJsonCodec codec = new ScimJsonCodec();

	private final ScimUserMapper mapper = new ScimUserMapper();

	@Test
	void appliesOperationsSequentiallyWithSdkPathAndFilterSemantics() throws Exception {
		ScimUserPatchRequest request = parse("""
				{
				  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				  "Operations": [
				    {"op":"replace", "path":"userName", "value":"patched-user"},
				    {"op":"replace", "path":"displayName", "value":"Patched User"},
				    {"op":"replace", "path":"name.givenName", "value":"Patched"},
				    {"op":"remove", "path":"name.familyName"},
				    {"op":"replace", "path":"emails[value eq \\\"alice@example.com\\\"].value",
				      "value":"patched@example.com"},
				    {"op":"remove", "path":"phoneNumbers[value eq \\\"tel:+15551234567\\\"]"},
				    {"op":"replace", "path":"active", "value":false}
				  ]
				}
				""");

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.identifiers()).containsExactly(LoginIdentifier.username("patched-user"),
				LoginIdentifier.email("patched@example.com"));
		assertThat(replacement.profile()).isEqualTo(
				new UserProfile("Patched User", "Alice Q. Jensen", "Patched", null));
		assertThat(replacement.active()).isFalse();
	}

	@Test
	void supportsPathlessUpdatesQualifiedPathsAndNoOpFilteredRemovals() throws Exception {
		ScimUserPatchRequest request = parse("""
				{
				  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				  "operations": [
				    {"op":"add", "value":{"displayName":"Updated", "name":{"familyName":"Updated"}}},
				    {"op":"replace",
				      "path":"urn:ietf:params:scim:schemas:core:2.0:User:name.formatted",
				      "value":"Updated Person"},
				    {"op":"remove", "path":"emails[value eq \\\"missing@example.com\\\"]"}
				  ]
				}
				""");

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.identifiers()).contains(LoginIdentifier.email("alice@example.com"));
		assertThat(replacement.profile()).isEqualTo(new UserProfile("Updated", "Updated Person", "Alice", "Updated"));
		assertThat(replacement.active()).isTrue();
	}

	@Test
	void rejectsInvalidEnvelopesOperationsAndPathsWithProtocolErrors() throws Exception {
		assertParseError("{\"Operations\":[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"x\"}]}",
				"invalidSyntax");
		assertParseError(patch("[]"), "invalidSyntax");
		assertParseError(patch("[{\"op\":\"move\",\"path\":\"displayName\",\"value\":\"x\"}]"),
				"invalidSyntax");
		assertParseError(patch("[{\"op\":\"remove\"}]"), "noTarget");
		assertParseError(patch("[{\"op\":\"remove\",\"path\":\"displayName\",\"value\":\"secret\"}]"),
				"invalidSyntax");
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"id\",\"value\":\"secret\"}]"),
				"mutability");
		assertParseError(patch("[{\"op\":\"remove\",\"path\":\"userName\"}]"), "mutability");
		assertParseError(patch("[{\"op\":\"remove\",\"path\":\"active\"}]"), "mutability");
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"nickName\",\"value\":\"secret\"}]"),
				"invalidPath");
		assertParseError(patch("[{\"op\":\"remove\",\"path\":\"emails[type eq \\\"secret\\\"]\"}]"),
				"invalidFilter");
		assertParseError(patch("[{\"op\":\"replace\",\"value\":{\"meta\":{\"secret\":true}}}]"),
				"mutability");
	}

	@Test
	void rejectsInvalidValuesAndUnmatchedReplaceWithoutReflectingInput() throws Exception {
		assertApplyError(patch("[{\"op\":\"replace\",\"path\":\"active\",\"value\":\"secret-active\"}]"),
				"invalidValue", "secret-active");
		assertApplyError(patch("[{\"op\":\"replace\",\"path\":\"emails[value eq \\\"secret@example.com\\\"].value\",\"value\":\"new@example.com\"}]"),
				"noTarget", "secret@example.com");
	}

	@Test
	void normalizesCaseInsensitivePathlessAttributeNames() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"replace","value":{"DisplayName":"Updated","Name":{"GivenName":"Updated"}}}]
				"""));

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.profile()).isEqualTo(
				new UserProfile("Updated", "Alice Q. Jensen", "Updated", "Jensen"));
	}

	@Test
	void treatsNullAsUnassignedWhileProtectingRequiredLifecycleAttributes() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"add","path":"displayName","value":null},
				 {"op":"replace","path":"name.givenName","value":null},
				 {"op":"add","value":{"name":{"familyName":null}}}]
				"""));

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.profile()).isEqualTo(new UserProfile(null, "Alice Q. Jensen", null, null));
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"userName\",\"value\":null}]"),
				"mutability");
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"active\",\"value\":null}]"),
				"mutability");
		assertParseError(patch("[{\"op\":\"replace\",\"value\":{\"active\":null}}]"), "mutability");
		assertApplyError(patch("[{\"op\":\"replace\",\"path\":\"emails[value eq \\\"missing@example.com\\\"].value\",\"value\":null}]"),
				"noTarget", "missing@example.com");
	}

	@Test
	void canonicalizesFilterAttributeCaseWithoutChangingItsLiteral() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"replace","path":"emails[VALUE eq \\\"alice@example.com\\\"].VALUE",
				  "value":"VALUE@example.com"}]
				"""));

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.identifiers()).contains(LoginIdentifier.email("value@example.com"));
	}

	@Test
	void addsComplexObjectsUsingSdkMergeAndMultivalueSemantics() throws Exception {
		User withoutEmail = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.username("alice"), LoginIdentifier.phone("+15551234567")),
				new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen"), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"add","path":"name","value":{"GivenName":"Updated"}},
				 {"op":"add","path":"emails","value":{"Value":"added@example.com"}}]
				"""));

		ReplaceUserRequest replacement = request.apply(withoutEmail, this.mapper, this.codec);

		assertThat(replacement.profile())
			.isEqualTo(new UserProfile("Alice Jensen", "Alice Q. Jensen", "Updated", "Jensen"));
		assertThat(replacement.identifiers()).containsExactly(LoginIdentifier.username("alice"),
				LoginIdentifier.email("added@example.com"), LoginIdentifier.phone("+15551234567"));
	}

	@Test
	void keepsEmailUserNameAndItsCollectionAliasConsistent() throws Exception {
		User emailOnly = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.email("primary@example.com")), UserProfile.empty(), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		ScimUserPatchRequest replaceAlias = parse(patch("""
				[{"op":"replace","path":"emails[VALUE eq \\\"primary@example.com\\\"].value",
				  "value":"changed@example.com"}]
				"""));

		ReplaceUserRequest changed = replaceAlias.apply(emailOnly, this.mapper, this.codec);

		assertThat(changed.identifiers()).containsExactly(LoginIdentifier.email("changed@example.com"));
		assertApplyError(patch("[{\"op\":\"remove\",\"path\":\"emails\"}]"), emailOnly,
				"invalidValue", null);

		ScimUserPatchRequest useUsername = parse(patch(
				"[{\"op\":\"replace\",\"path\":\"userName\",\"value\":\"ordinary-user\"}]"));
		assertThat(useUsername.apply(emailOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.username("ordinary-user"), LoginIdentifier.email("primary@example.com"));

		ScimUserPatchRequest changePrimaryEmail = parse(patch(
				"[{\"op\":\"replace\",\"path\":\"userName\",\"value\":\"new-primary@example.com\"}]"));
		assertThat(changePrimaryEmail.apply(emailOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.email("new-primary@example.com"));
	}

	@Test
	void removesSupportedComplexValuesWithoutLeavingEmptyObjects() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"remove","path":"emails[VALUE eq \\\"alice@example.com\\\"].value"},
				 {"op":"replace","path":"phoneNumbers.value","value":null}]
				"""));

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.identifiers()).containsExactly(LoginIdentifier.username("alice"));
	}

	@Test
	void rejectsAliasChangesThatWouldDiscardOrShadowAnExistingIdentifier() throws Exception {
		String noOpBypass = patch("""
				[{"op":"remove","path":"emails[value eq \\\"missing@example.com\\\"]"},
				 {"op":"replace","path":"userName","value":"replacement@example.com"}]
				""");
		assertApplyError(noOpBypass, "invalidValue", "replacement@example.com");

		User emailOnly = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.email("primary@example.com")), UserProfile.empty(), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		String shadowed = patch(
				"[{\"op\":\"replace\",\"path\":\"userName\",\"value\":\"+15551234567\"}]");
		assertApplyError(shadowed, emailOnly, "invalidValue", null);

		ScimUserPatchRequest explicitChange = parse(patch("""
				[{"op":"remove","path":"emails"},
				 {"op":"replace","path":"userName","value":"+15551234567"}]
				"""));
		assertThat(explicitChange.apply(emailOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.phone("+15551234567"));
	}

	@Test
	void synchronizesFilteredChangesForAPhoneUserNameAlias() throws Exception {
		User phoneOnly = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.phone("+15551234567")), UserProfile.empty(), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"replace","path":"phoneNumbers[VaLuE eq \\\"tel:+15551234567\\\"].value",
				  "value":"tel:+15557654321"}]
				"""));

		assertThat(request.apply(phoneOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.phone("+15557654321"));
	}

	@Test
	void rejectsEmptyArraysForSingleValuedAttributesOnly() throws Exception {
		for (String operation : List.of(
				"{\"op\":\"replace\",\"path\":\"displayName\",\"value\":[]}",
				"{\"op\":\"replace\",\"path\":\"name\",\"value\":[]}",
				"{\"op\":\"replace\",\"path\":\"name.givenName\",\"value\":[]}",
				"{\"op\":\"replace\",\"path\":\"emails.value\",\"value\":[]}",
				"{\"op\":\"replace\",\"value\":{\"displayName\":[]}}",
				"{\"op\":\"add\",\"value\":{\"name\":{\"givenName\":[]}}}",
				"{\"op\":\"replace\",\"value\":{\"name\":{\"givenName\":[]}}}")) {
			assertParseError(patch("[" + operation + "]"), "invalidValue");
		}

		ScimUserPatchRequest clear = parse(patch(
				"[{\"op\":\"replace\",\"path\":\"emails\",\"value\":[]}]"));
		assertThat(clear.apply(user(), this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.username("alice"), LoginIdentifier.phone("+15551234567"));
	}

	@Test
	void createsMissingComplexParentsForSubAttributeAddAndReplace() throws Exception {
		User usernameOnly = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.username("alice")), UserProfile.empty(), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"add","path":"emails.value","value":"ADDED@Example.com"},
				 {"op":"replace","path":"phoneNumbers.value","value":"+1 (555) 765-4321"}]
				"""));

		assertThat(request.apply(usernameOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.username("alice"), LoginIdentifier.email("added@example.com"),
					LoginIdentifier.phone("+15557654321"));
	}

	@Test
	void makesCanonicalComplexAddsIdempotent() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"add","path":"emails","value":{"value":"ALICE@Example.com"}},
				 {"op":"add","path":"phoneNumbers","value":{"value":"+1 (555) 123-4567"}}]
				"""));

		ReplaceUserRequest replacement = request.apply(user(), this.mapper, this.codec);

		assertThat(replacement.identifiers()).isEqualTo(user().identifiers());
	}

	@Test
	void appliesFilteredAddsUsingTheRequestedValueInsteadOfTheSelector() throws Exception {
		ScimUserPatchRequest replaceMatch = parse(patch("""
				[{"op":"add","path":"emails[value eq \\"alice@example.com\\"].value",
				  "value":"desired@example.com"}]
				"""));
		assertThat(replaceMatch.apply(user(), this.mapper, this.codec).identifiers())
			.contains(LoginIdentifier.email("desired@example.com"));

		User usernameOnly = new User(UserId.random(), TenantId.random(),
				List.of(LoginIdentifier.username("alice")), UserProfile.empty(), UserStatus.ACTIVE,
				4, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null);
		ScimUserPatchRequest addMissing = parse(patch("""
				[{"op":"add","path":"emails[value eq \\"selector@example.com\\"].value",
				  "value":"desired@example.com"}]
				"""));
		assertThat(addMissing.apply(usernameOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.username("alice"), LoginIdentifier.email("desired@example.com"));

		ScimUserPatchRequest replaceComplexMatch = parse(patch("""
				[{"op":"add","path":"emails[value eq \\"alice@example.com\\"]",
				  "value":{"value":"complex-match@example.com"}}]
				"""));
		assertThat(replaceComplexMatch.apply(user(), this.mapper, this.codec).identifiers())
			.contains(LoginIdentifier.email("complex-match@example.com"));

		ScimUserPatchRequest addMissingComplex = parse(patch("""
				[{"op":"add","path":"emails[value eq \\"selector@example.com\\"]",
				  "value":{"value":"complex-missing@example.com"}}]
				"""));
		assertThat(addMissingComplex.apply(usernameOnly, this.mapper, this.codec).identifiers())
			.containsExactly(LoginIdentifier.username("alice"), LoginIdentifier.email("complex-missing@example.com"));
	}

	@Test
	void replacesAFilteredComplexObjectWithoutCreatingANestedArray() throws Exception {
		ScimUserPatchRequest request = parse(patch("""
				[{"op":"replace","path":"emails[value eq \\\"alice@example.com\\\"]",
				  "value":{"VALUE":"replacement@example.com"}}]
				"""));

		assertThat(request.apply(user(), this.mapper, this.codec).identifiers())
			.contains(LoginIdentifier.email("replacement@example.com"));
	}

	@Test
	void rejectsAnInvalidIntermediateOperationEvenWhenALaterOperationWouldRepairIt() throws Exception {
		assertApplyError(patch("""
				[{"op":"replace","path":"active","value":"invalid-active"},
				 {"op":"replace","path":"active","value":true}]
				"""), "invalidValue", "invalid-active");
	}

	@Test
	void boundsOperationsJsonValuesAndFilterComplexity() throws Exception {
		String operations = IntStream.range(0, 101)
			.mapToObj((index) -> "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"bounded\"}")
			.collect(Collectors.joining(",", "[", "]"));
		assertParseError(patch(operations), "tooMany");

		String oversized = "x".repeat(65_537);
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + oversized
				+ "\"}]"), "tooMany");

		String values = IntStream.range(0, 2_049).mapToObj(Integer::toString)
			.collect(Collectors.joining(",", "[", "]"));
		assertParseError(patch("[{\"op\":\"replace\",\"path\":\"emails\",\"value\":" + values + "}]"),
				"tooMany");

		String filter = "not (".repeat(17) + "value eq \"bounded\"" + ")".repeat(17);
		assertParseError(patch("[{\"op\":\"remove\",\"path\":\"emails[" + filter.replace("\"", "\\\"")
				+ "]\"}]"), "invalidFilter");
	}

	private ScimUserPatchRequest parse(String json) throws JacksonException, BadRequestException {
		return ScimUserPatchRequest.parse((ObjectNode) this.codec.jsonMapper().readTree(json));
	}

	private void assertParseError(String json, String scimType) throws Exception {
		assertThatExceptionOfType(BadRequestException.class)
			.isThrownBy(() -> parse(json))
			.satisfies((exception) -> assertThat(exception.getScimError().getScimType()).isEqualTo(scimType));
	}

	private void assertApplyError(String json, String scimType, String secret) throws Exception {
		assertApplyError(json, user(), scimType, secret);
	}

	private void assertApplyError(String json, User target, String scimType, String secret) throws Exception {
		ScimUserPatchRequest request = parse(json);
		assertThatExceptionOfType(BadRequestException.class)
			.isThrownBy(() -> request.apply(target, this.mapper, this.codec))
			.satisfies((exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo(scimType);
				if (secret != null) {
					assertThat(exception.getScimError().getDetail()).doesNotContain(secret);
				}
			});
	}

	private static String patch(String operations) {
		return "{\"schemas\":[\"" + ScimUserPatchRequest.SCHEMA_URN + "\"],\"Operations\":" + operations + "}";
	}

	private static User user() {
		return new User(UserId.random(), TenantId.random(), List.of(LoginIdentifier.username("alice"),
				LoginIdentifier.email("alice@example.com"), LoginIdentifier.phone("+15551234567")),
				new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen"), UserStatus.ACTIVE, 4, 2,
				CREATED_AT, CREATED_AT.plusSeconds(60), null);
	}

}
