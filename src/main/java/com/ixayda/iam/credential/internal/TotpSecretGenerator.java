package com.ixayda.iam.credential.internal;

import java.security.SecureRandom;
import java.util.Objects;

final class TotpSecretGenerator {

	private final SecureRandom random;

	TotpSecretGenerator() {
		this(new SecureRandom());
	}

	TotpSecretGenerator(SecureRandom random) {
		this.random = Objects.requireNonNull(random, "Secure random generator must not be null");
	}

	byte[] generate() {
		byte[] secret = new byte[TotpSecretCipher.SECRET_BYTES];
		this.random.nextBytes(secret);
		return secret;
	}

}
