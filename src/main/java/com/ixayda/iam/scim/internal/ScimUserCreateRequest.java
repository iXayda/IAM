package com.ixayda.iam.scim.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.ReplaceUserRequest;
import com.ixayda.iam.user.UserProfile;
import com.unboundid.scim2.common.exceptions.BadRequestException;
import com.unboundid.scim2.common.types.Email;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.PhoneNumber;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.node.ObjectNode;

record ScimUserCreateRequest(CreateUserRequest request, Boolean active) {

	private static final String INVALID_DETAIL = "The SCIM User request contains an invalid or unsupported value.";

	static ScimUserCreateRequest parse(ObjectNode source, ScimJsonCodec codec) throws BadRequestException {
		if (source == null) {
			throw invalid();
		}
		ObjectNode writable = source.deepCopy();
		List<String> readOnly = writable.propertyNames().stream()
			.filter((name) -> name.equalsIgnoreCase("id") || name.equalsIgnoreCase("meta")
					|| name.equalsIgnoreCase("groups"))
			.toList();
		writable.remove(readOnly);
		try {
			return parse(codec.jsonMapper().treeToValue(writable, ScimUserCreateResource.class));
		}
		catch (JacksonException exception) {
			throw invalid();
		}
	}

	static ScimUserCreateRequest parse(ScimUserCreateResource resource) throws BadRequestException {
		if (resource == null) {
			throw invalid();
		}
		validateSchemas(resource);
		validateSupportedAttributes(resource);
		try {
			List<LoginIdentifier> identifiers = new ArrayList<>();
			addIdentifier(identifiers, primaryIdentifier(resource.getUserName()));
			addEmail(identifiers, resource.getEmails());
			addPhone(identifiers, resource.getPhoneNumbers());
			Name name = resource.getName();
			UserProfile profile = new UserProfile(resource.getDisplayName(), name == null ? null : name.getFormatted(),
					name == null ? null : name.getGivenName(), name == null ? null : name.getFamilyName());
			return new ScimUserCreateRequest(new CreateUserRequest(identifiers, profile), resource.getActive());
		}
		catch (RuntimeException exception) {
			throw invalid();
		}
	}

	boolean activeOrDefault() {
		return !Boolean.FALSE.equals(this.active);
	}

	ReplaceUserRequest replacement() {
		return new ReplaceUserRequest(this.request.identifiers(), this.request.profile(), this.active);
	}

	private static void validateSchemas(ScimUserCreateResource resource) throws BadRequestException {
		if (!resource.schemasProvided() || !resource.schemasValid()
				|| !resource.getSchemaUrns().equals(Set.of(ScimUserSchema.URN))
				|| !resource.getExtensionObjectNode().isEmpty()) {
			throw invalid();
		}
	}

	private static void validateSupportedAttributes(ScimUserCreateResource resource) throws BadRequestException {
		Name name = resource.getName();
		if (resource.getExternalId() != null || resource.getNickName() != null || resource.getProfileUrl() != null
				|| resource.getTitle() != null || resource.getUserType() != null || resource.getPreferredLanguage() != null
				|| resource.getLocale() != null || resource.getTimezone() != null || resource.getPassword() != null
				|| isPresent(resource.getIms()) || isPresent(resource.getPhotos()) || isPresent(resource.getAddresses())
				|| isPresent(resource.getEntitlements()) || isPresent(resource.getRoles())
				|| isPresent(resource.getX509Certificates()) || name != null && (name.getMiddleName() != null
						|| name.getHonorificPrefix() != null || name.getHonorificSuffix() != null)) {
			throw invalid();
		}
		validateEmailAttributes(resource.getEmails());
		validatePhoneAttributes(resource.getPhoneNumbers());
	}

	private static void validateEmailAttributes(List<Email> emails) throws BadRequestException {
		if (emails == null) {
			return;
		}
		for (Email email : emails) {
			if (email == null || email.getDisplay() != null || email.getType() != null || email.getPrimary() != null) {
				throw invalid();
			}
		}
	}

	private static void validatePhoneAttributes(List<PhoneNumber> phoneNumbers) throws BadRequestException {
		if (phoneNumbers == null) {
			return;
		}
		for (PhoneNumber phoneNumber : phoneNumbers) {
			if (phoneNumber == null || phoneNumber.getDisplay() != null || phoneNumber.getType() != null
					|| phoneNumber.getPrimary() != null) {
				throw invalid();
			}
		}
	}

	private static boolean isPresent(List<?> values) {
		return values != null && !values.isEmpty();
	}

	private static LoginIdentifier primaryIdentifier(String userName) {
		if (userName == null) {
			throw new IllegalArgumentException("SCIM userName is required");
		}
		if (userName.indexOf('@') >= 0) {
			return LoginIdentifier.email(userName);
		}
		String phone = telephoneValue(userName);
		try {
			return LoginIdentifier.phone(phone);
		}
		catch (IllegalArgumentException exception) {
			if (!phone.equals(userName)) {
				throw exception;
			}
			return LoginIdentifier.username(userName);
		}
	}

	private static void addEmail(List<LoginIdentifier> identifiers, List<Email> emails) {
		if (emails == null || emails.isEmpty()) {
			return;
		}
		if (emails.size() != 1 || emails.getFirst() == null) {
			throw new IllegalArgumentException("Only one SCIM email value is supported");
		}
		addIdentifier(identifiers, LoginIdentifier.email(emails.getFirst().getValue()));
	}

	private static void addPhone(List<LoginIdentifier> identifiers, List<PhoneNumber> phoneNumbers) {
		if (phoneNumbers == null || phoneNumbers.isEmpty()) {
			return;
		}
		if (phoneNumbers.size() != 1 || phoneNumbers.getFirst() == null) {
			throw new IllegalArgumentException("Only one SCIM phone number value is supported");
		}
		addIdentifier(identifiers, LoginIdentifier.phone(telephoneValue(phoneNumbers.getFirst().getValue())));
	}

	private static String telephoneValue(String value) {
		if (value != null && value.regionMatches(true, 0, "tel:", 0, 4)) {
			return value.substring(4);
		}
		return value;
	}

	private static void addIdentifier(List<LoginIdentifier> identifiers, LoginIdentifier candidate) {
		for (LoginIdentifier existing : identifiers) {
			if (existing.type() == candidate.type()) {
				if (existing.canonicalValue().equals(candidate.canonicalValue())) {
					return;
				}
				throw new IllegalArgumentException("Only one login identifier of each type is supported");
			}
		}
		identifiers.add(candidate);
	}

	private static BadRequestException invalid() {
		return BadRequestException.invalidValue(INVALID_DETAIL);
	}

}
