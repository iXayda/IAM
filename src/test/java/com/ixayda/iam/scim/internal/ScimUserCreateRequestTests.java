package com.ixayda.iam.scim.internal;

import java.net.URI;
import java.util.List;
import java.util.Set;

import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.UserProfile;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.Email;
import com.unboundid.scim2.common.types.Meta;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.PhoneNumber;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScimUserCreateRequestTests {

	@Test
	void mapsTheSupportedCreateAttributesAndIgnoresReadOnlyValues() throws Exception {
		ScimUserCreateResource resource = resource();
		resource.setUserName("alice")
			.setDisplayName("Alice Jensen")
			.setName(new Name().setFormatted("Alice Q. Jensen").setGivenName("Alice").setFamilyName("Jensen"))
			.setEmails(new Email().setValue("Alice@Example.com"))
			.setPhoneNumbers(new PhoneNumber().setValue("tel:+1-555-123-4567"))
			.setActive(false);
		resource.setId("client-controlled-id");
		resource.setMeta(new Meta().setLocation(URI.create("https://attacker.example.test/Users/1")));

		ScimUserCreateRequest parsed = ScimUserCreateRequest.parse(resource);

		assertThat(parsed.active()).isFalse();
		assertThat(parsed.request().identifiers()).containsExactly(
				LoginIdentifier.username("alice"), LoginIdentifier.email("Alice@Example.com"),
				LoginIdentifier.phone("+1-555-123-4567"));
		assertThat(parsed.request().profile())
			.isEqualTo(new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen"));
	}

	@Test
	void infersEmailAndPhoneUserNamesAndDeduplicatesTheirCanonicalValues() throws Exception {
		ScimUserCreateResource email = resource();
		email.setUserName("Alice@Example.com").setEmails(new Email().setValue("alice@example.COM"));
		ScimUserCreateResource phone = resource();
		phone.setUserName("tel:+1 (555) 123-4567").setPhoneNumbers(new PhoneNumber().setValue("+15551234567"));

		assertThat(ScimUserCreateRequest.parse(email).request().identifiers())
			.containsExactly(LoginIdentifier.email("Alice@Example.com"));
		assertThat(ScimUserCreateRequest.parse(phone).request().identifiers())
			.containsExactly(LoginIdentifier.phone("+1 (555) 123-4567"));
	}

	@Test
	void rejectsMissingConflictingOrUnsupportedValuesWithoutReflectingThem() {
		assertInvalid(resource());
		ScimUserCreateResource multipleEmails = resource();
		multipleEmails.setUserName("alice").setEmails(
				List.of(new Email().setValue("one@example.com"), new Email().setValue("two@example.com")));
		assertInvalid(multipleEmails);
		ScimUserCreateResource conflictingEmail = resource();
		conflictingEmail.setUserName("alice@example.com").setEmails(new Email().setValue("different@example.com"));
		assertInvalid(conflictingEmail);
		ScimUserCreateResource password = resource();
		password.setUserName("alice").setPassword("secret-password-value");
		assertInvalid(password);
		ScimUserCreateResource middleName = resource();
		middleName.setUserName("alice").setName(new Name().setMiddleName("secret-middle-name"));
		assertInvalid(middleName);
		ScimUserCreateResource emailMetadata = resource();
		emailMetadata.setUserName("alice").setEmails(new Email().setValue("alice@example.com").setType("work"));
		assertInvalid(emailMetadata);
		ScimUserCreateResource phoneMetadata = resource();
		phoneMetadata.setUserName("alice")
			.setPhoneNumbers(new PhoneNumber().setValue("tel:+15551234567").setPrimary(true));
		assertInvalid(phoneMetadata);

		ScimUserCreateResource wrongSchema = resource();
		wrongSchema.setUserName("alice");
		wrongSchema.setSchemaUrns(Set.of("urn:example:unsupported:User"));
		assertInvalid(wrongSchema);
		ScimUserCreateResource duplicateSchema = resource();
		duplicateSchema.setUserName("alice");
		duplicateSchema.setSchemaUrns(List.of(ScimUserSchema.URN, ScimUserSchema.URN));
		assertInvalid(duplicateSchema);

		ScimUserCreateResource missingSchemas = new ScimUserCreateResource();
		missingSchemas.setUserName("alice");
		assertInvalid(missingSchemas);
		ScimUserCreateResource nullSchemas = resource();
		nullSchemas.setUserName("alice");
		nullSchemas.setSchemaUrns(null);
		assertInvalid(nullSchemas);
	}

	private static ScimUserCreateResource resource() {
		ScimUserCreateResource resource = new ScimUserCreateResource();
		resource.setSchemaUrns(Set.of(ScimUserSchema.URN));
		return resource;
	}

	private static void assertInvalid(ScimUserCreateResource resource) {
		assertThatThrownBy(() -> ScimUserCreateRequest.parse(resource))
			.isInstanceOfSatisfying(BadRequestException.class, (exception) -> {
				assertThat(exception.getScimError().getScimType()).isEqualTo("invalidValue");
				assertThat(exception.getMessage()).doesNotContain("secret-password-value", "secret-middle-name");
			});
	}

}
