package com.ixayda.iam.user;

import java.util.List;

public record CreateUserRequest(List<LoginIdentifier> identifiers) {

	public CreateUserRequest {
		identifiers = LoginIdentifier.validatedCopy(identifiers);
	}

	@Override
	public String toString() {
		return "CreateUserRequest[identifierCount=" + this.identifiers.size() + "]";
	}

}
