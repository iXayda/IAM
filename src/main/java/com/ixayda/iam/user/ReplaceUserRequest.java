package com.ixayda.iam.user;

import java.util.List;
import java.util.Objects;

/**
 * Complete replacement of the writable user directory attributes. A null active
 * value preserves the current lifecycle state.
 */
public record ReplaceUserRequest(List<LoginIdentifier> identifiers, UserProfile profile, Boolean active) {

	public ReplaceUserRequest {
		identifiers = LoginIdentifier.validatedCopy(identifiers);
		Objects.requireNonNull(profile, "User profile must not be null");
	}

	@Override
	public String toString() {
		return "ReplaceUserRequest[identifierCount=" + this.identifiers.size() + ", profilePresent="
				+ !this.profile.isEmpty() + ", activeSpecified=" + (this.active != null) + "]";
	}

}
