package com.ixayda.iam.model;

import java.security.PrivateKey;
import java.util.Objects;

/** Internal signing capability, supplied only to trusted protocol code. */
public record IdentitySigningMaterial(IdentitySigningKey key, PrivateKey privateKey) {

	public IdentitySigningMaterial {
		Objects.requireNonNull(key, "Signing identity is required");
		Objects.requireNonNull(privateKey, "Signing private key is required");
	}

	@Override
	public String toString() {
		return "IdentitySigningMaterial[id=" + this.key.id() + ", algorithm=" + this.key.algorithm() + ", privateKey=REDACTED]";
	}

}
