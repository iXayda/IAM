package com.ixayda.iam.credential;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

/** Server-generated high-entropy credentials encoded for Spring's delegating password verifier. */
@Component
public final class ClientSecrets {

	private final SecureRandom random = new SecureRandom();
	private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);

	public String generate() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String hash(String secret) {
		if (secret == null || !secret.matches("[A-Za-z0-9_-]{43}")
				|| !Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(secret)).equals(secret)) {
			throw new IllegalArgumentException("A generated client secret is required");
		}
		return "{argon2}" + this.encoder.encode(secret);
	}

}
