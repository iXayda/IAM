package com.ixayda.iam.credential;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/** Server-generated high-entropy credentials, hashed and verified with Spring's Argon2id implementation. */
@Component
public final class ClientSecrets {

	private static final Pattern HASH = Pattern.compile("\\{argon2}\\$argon2id\\$v=19\\$m=19456,t=2,p=1\\$([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})");
	private final SecureRandom random = new SecureRandom();
	private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
	private final PasswordEncoder verifier = new PasswordEncoder() {
		@Override
		public String encode(CharSequence rawPassword) { throw new UnsupportedOperationException("Client secrets require audited management"); }

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			if (rawPassword == null || rawPassword.length() != 43 || !isSupportedHash(encodedPassword)) { return false; }
			String secret = rawPassword.toString();
			return isGeneratedSecret(secret) && encoder.matches(secret, encodedPassword.substring("{argon2}".length()));
		}
	};

	public String generate() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String hash(String secret) {
		if (!isGeneratedSecret(secret)) {
			throw new IllegalArgumentException("A generated client secret is required");
		}
		return "{argon2}" + this.encoder.encode(secret);
	}

	/** Read-only Spring verifier; successful authentication cannot silently rehash a managed credential. */
	public PasswordEncoder verifier() { return this.verifier; }

	/** Bound parameters and canonical encodings before handing stored input to the Argon2 implementation. */
	public boolean isSupportedHash(String hash) {
		if (hash == null) { return false; }
		var matcher = HASH.matcher(hash);
		return matcher.matches() && canonicalBase64(matcher.group(1)) && canonicalBase64(matcher.group(2));
	}

	private static boolean canonicalBase64(String value) {
		return Base64.getEncoder().withoutPadding().encodeToString(Base64.getDecoder().decode(value)).equals(value);
	}

	private static boolean isGeneratedSecret(String secret) {
		return secret != null && secret.matches("[A-Za-z0-9_-]{43}")
				&& Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(secret)).equals(secret);
	}

}
