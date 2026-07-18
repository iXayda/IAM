package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.UserResource;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimUserMapperTests {

	private static final URI LOCATION =
			URI.create("https://scim.example.test/scim/v2/Users/00000000-0000-0000-0000-000000000101");

	private static final Instant CREATED_AT = Instant.parse("2026-07-19T01:02:03Z");

	private static final Instant UPDATED_AT = Instant.parse("2026-07-19T02:03:04Z");

	private final ScimUserMapper mapper = new ScimUserMapper();

	@Test
	void mapsTheSupportedUserSchemaWithoutSensitiveOrUnbackedAttributes() throws Exception {
		UserResource resource = this.mapper.map(user(UserStatus.ACTIVE), LOCATION,
				ScimUserAttributeSelection.parse(null, null));

		assertThat(resource.getSchemaUrns()).containsExactly(ScimUserSchema.URN);
		assertThat(resource.getId()).isEqualTo("00000000-0000-0000-0000-000000000101");
		assertThat(resource.getUserName()).isEqualTo("alice");
		assertThat(resource.getDisplayName()).isEqualTo("Alice Jensen");
		assertThat(resource.getName().getFormatted()).isEqualTo("Alice Q. Jensen");
		assertThat(resource.getName().getGivenName()).isEqualTo("Alice");
		assertThat(resource.getName().getFamilyName()).isEqualTo("Jensen");
		assertThat(resource.getEmails()).singleElement().extracting("value").isEqualTo("alice@example.com");
		assertThat(resource.getPhoneNumbers()).singleElement().extracting("value").isEqualTo("tel:+15551234567");
		assertThat(resource.getActive()).isTrue();
		assertThat(resource.getPassword()).isNull();
		assertThat(resource.getGroups()).isNull();
		assertThat(resource.getExternalId()).isNull();
		assertThat(resource.getMeta().getResourceType()).isEqualTo("User");
		assertThat(resource.getMeta().getLocation()).isEqualTo(LOCATION);
		assertThat(resource.getMeta().getCreated().toInstant()).isEqualTo(CREATED_AT);
		assertThat(resource.getMeta().getLastModified().toInstant()).isEqualTo(UPDATED_AT);
		assertThat(resource.getMeta().getVersion()).isNull();
	}

	@Test
	void mapsNonActiveLifecycleStatesAsInactive() throws Exception {
		assertThat(this.mapper.map(user(UserStatus.DISABLED), LOCATION,
				ScimUserAttributeSelection.parse(null, null)).getActive()).isFalse();
		assertThat(this.mapper.map(user(UserStatus.LOCKED), LOCATION,
				ScimUserAttributeSelection.parse(null, null)).getActive()).isFalse();
	}

	@Test
	void appliesIncludedAndExcludedSubAttributes() throws Exception {
		ScimUserAttributeSelection included = ScimUserAttributeSelection.parse(
				List.of("displayName,name.givenName", ScimUserSchema.URN + ":emails.value"), null);
		UserResource includedResource = this.mapper.map(user(UserStatus.ACTIVE), LOCATION, included);

		assertThat(includedResource.getId()).isNotNull();
		assertThat(includedResource.getDisplayName()).isEqualTo("Alice Jensen");
		assertThat(includedResource.getName().getGivenName()).isEqualTo("Alice");
		assertThat(includedResource.getName().getFormatted()).isNull();
		assertThat(includedResource.getName().getFamilyName()).isNull();
		assertThat(includedResource.getEmails()).singleElement().extracting("value")
			.isEqualTo("alice@example.com");
		assertThat(includedResource.getUserName()).isNull();
		assertThat(includedResource.getPhoneNumbers()).isNull();
		assertThat(includedResource.getActive()).isNull();
		assertThat(includedResource.getMeta()).isNull();

		ScimUserAttributeSelection excluded = ScimUserAttributeSelection.parse(null,
				List.of("EMAILS,name.familyName,meta.created"));
		UserResource excludedResource = this.mapper.map(user(UserStatus.ACTIVE), LOCATION, excluded);

		assertThat(excludedResource.getUserName()).isEqualTo("alice");
		assertThat(excludedResource.getEmails()).isNull();
		assertThat(excludedResource.getName().getGivenName()).isEqualTo("Alice");
		assertThat(excludedResource.getName().getFamilyName()).isNull();
		assertThat(excludedResource.getMeta().getCreated()).isNull();
		assertThat(excludedResource.getMeta().getLastModified()).isNotNull();
	}

	@Test
	void fallsBackToCanonicalEmailAndPhoneUserNames() throws Exception {
		User emailUser = user(UserStatus.ACTIVE, List.of(LoginIdentifier.email("Alice@Example.com")));
		User phoneUser = user(UserStatus.ACTIVE, List.of(LoginIdentifier.phone("+1 (555) 123-4567")));

		assertThat(this.mapper.map(emailUser, LOCATION,
				ScimUserAttributeSelection.parse(null, null)).getUserName()).isEqualTo("Alice@Example.com");
		assertThat(this.mapper.map(phoneUser, LOCATION,
				ScimUserAttributeSelection.parse(null, null)).getUserName()).isEqualTo("+1 (555) 123-4567");
	}

	@Test
	void rejectsUnsupportedAttributePaths() {
		assertThatThrownBy(() -> ScimUserAttributeSelection.parse(
				List.of("urn:ietf:params:scim:schemas:extension:example:2.0:User:displayName"), null))
			.isInstanceOf(BadRequestException.class);
		assertThatThrownBy(() -> ScimUserAttributeSelection.parse(List.of("emails[value eq secret]"), null))
			.isInstanceOf(BadRequestException.class);
		assertThatThrownBy(() -> ScimUserAttributeSelection.parse(List.of("name.givenName.value"), null))
			.isInstanceOf(BadRequestException.class);
	}

	private static User user(UserStatus status) {
		return user(status, List.of(LoginIdentifier.username("alice"), LoginIdentifier.email("Alice@Example.com"),
				LoginIdentifier.phone("+1 (555) 123-4567")));
	}

	private static User user(UserStatus status, List<LoginIdentifier> identifiers) {
		return new User(new UserId(UUID.fromString("00000000-0000-0000-0000-000000000101")), TenantId.DEFAULT,
				identifiers,
				new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen"), status, 7, 3,
				CREATED_AT, UPDATED_AT, null);
	}

}
