package com.ixayda.iam.client;

import java.util.Objects;

public final class ClientAlreadyExistsException extends RuntimeException {

	private final ClientIdentifier identifier;

	public ClientAlreadyExistsException(ClientIdentifier identifier) {
		super("OAuth client identifier is already registered: " + Objects.requireNonNull(identifier));
		this.identifier = identifier;
	}

	public ClientIdentifier identifier() {
		return this.identifier;
	}

}
