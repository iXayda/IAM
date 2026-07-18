package com.ixayda.iam.scim.internal;

import java.net.URI;

import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginIdentifierType;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserProfile;
import com.ixayda.iam.user.UserStatus;
import com.unboundid.scim2.common.types.Email;
import com.unboundid.scim2.common.types.Meta;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.PhoneNumber;
import com.unboundid.scim2.common.types.UserResource;
import org.springframework.stereotype.Component;

@Component
final class ScimUserMapper {

	UserResource map(User user, URI location, ScimUserAttributeSelection selection) {
		if (user.isDeleted()) {
			throw new IllegalArgumentException("Deleted users cannot be mapped to SCIM resources");
		}
		UserResource resource = new UserResource();
		resource.setId(user.id().toString());
		if (selection.includes("userName")) {
			resource.setUserName(primaryIdentifier(user).value());
		}
		if (selection.includes("displayName")) {
			resource.setDisplayName(user.profile().displayName());
		}
		resource.setName(name(user.profile(), selection));
		resource.setEmails(emails(user, selection));
		resource.setPhoneNumbers(phoneNumbers(user, selection));
		if (selection.includes("active")) {
			resource.setActive(user.status() == UserStatus.ACTIVE);
		}
		resource.setMeta(metadata(user, location, selection));
		return resource;
	}

	private static Name name(UserProfile profile, ScimUserAttributeSelection selection) {
		Name name = new Name();
		boolean present = false;
		if (selection.includes("name", "formatted") && profile.formattedName() != null) {
			name.setFormatted(profile.formattedName());
			present = true;
		}
		if (selection.includes("name", "givenName") && profile.givenName() != null) {
			name.setGivenName(profile.givenName());
			present = true;
		}
		if (selection.includes("name", "familyName") && profile.familyName() != null) {
			name.setFamilyName(profile.familyName());
			present = true;
		}
		return present ? name : null;
	}

	private static java.util.List<Email> emails(User user, ScimUserAttributeSelection selection) {
		if (!selection.includes("emails", "value")) {
			return null;
		}
		return user.identifiers().stream()
			.filter((identifier) -> identifier.type() == LoginIdentifierType.EMAIL)
			.map((identifier) -> new Email().setValue(identifier.canonicalValue()))
			.toList();
	}

	private static java.util.List<PhoneNumber> phoneNumbers(User user, ScimUserAttributeSelection selection) {
		if (!selection.includes("phoneNumbers", "value")) {
			return null;
		}
		return user.identifiers().stream()
			.filter((identifier) -> identifier.type() == LoginIdentifierType.PHONE)
			.map((identifier) -> new PhoneNumber().setValue("tel:+" + identifier.canonicalValue()))
			.toList();
	}

	private static Meta metadata(User user, URI location, ScimUserAttributeSelection selection) {
		Meta metadata = new Meta();
		boolean present = false;
		if (selection.includes("meta", "resourceType")) {
			metadata.setResourceType("User");
			present = true;
		}
		if (selection.includes("meta", "created")) {
			metadata.setCreatedMillis(user.createdAt().toEpochMilli());
			present = true;
		}
		if (selection.includes("meta", "lastModified")) {
			metadata.setLastModifiedMillis(user.updatedAt().toEpochMilli());
			present = true;
		}
		if (selection.includes("meta", "location")) {
			metadata.setLocation(location);
			present = true;
		}
		return present ? metadata : null;
	}

	private static LoginIdentifier primaryIdentifier(User user) {
		for (LoginIdentifierType type : LoginIdentifierType.values()) {
			for (LoginIdentifier identifier : user.identifiers()) {
				if (identifier.type() == type) {
					return identifier;
				}
			}
		}
		throw new IllegalStateException("User has no login identifier");
	}

}
