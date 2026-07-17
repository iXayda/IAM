package com.ixayda.iam.user;

import java.util.List;
import java.util.Objects;

public record CreateUserRequest(List<LoginIdentifier> identifiers, UserProfile profile) {

	public CreateUserRequest(List<LoginIdentifier> identifiers) {
		this(identifiers, UserProfile.empty());
	}

	public CreateUserRequest {
		identifiers = LoginIdentifier.validatedCopy(identifiers);
		Objects.requireNonNull(profile, "User profile must not be null");
	}

	@Override
	public String toString() {
		return "CreateUserRequest[identifierCount=" + this.identifiers.size() + ", profilePresent="
				+ !this.profile.isEmpty() + "]";
	}

}
