package com.ixayda.iam.model;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Public signing identity; contains no private or encrypted private material. */
public record IdentitySigningKey(UUID id, String algorithm, RSAPublicKey publicKey, Instant createdAt) {

	public IdentitySigningKey {
		Objects.requireNonNull(id, "Signing key id is required");
		if (!"RS256".equals(algorithm)) { throw new IllegalArgumentException("Signing algorithm must be RS256"); }
		Objects.requireNonNull(publicKey, "Signing public key is required");
		Objects.requireNonNull(createdAt, "Signing key creation time is required");
	}

}
