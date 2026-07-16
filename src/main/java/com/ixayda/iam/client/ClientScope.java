package com.ixayda.iam.client;

import java.util.Objects;

public record ClientScope(String value) {

	private static final int MAX_LENGTH = 128;

	public ClientScope {
		Objects.requireNonNull(value, "Client scope must not be null");
		if (value.isEmpty() || value.length() > MAX_LENGTH || !value.chars().allMatch(ClientScope::isScopeCharacter)) {
			throw new IllegalArgumentException("Client scope must contain 1 to 128 valid OAuth scope-token characters");
		}
	}

	private static boolean isScopeCharacter(int character) {
		return character == 0x21 || character >= 0x23 && character <= 0x5b
				|| character >= 0x5d && character <= 0x7e;
	}

	@Override
	public String toString() {
		return this.value;
	}

}
