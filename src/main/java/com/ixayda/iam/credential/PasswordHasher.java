package com.ixayda.iam.credential;

import java.util.regex.Pattern;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

/** Creates salted Argon2id hashes and verifies passwords without reapplying setting rules. */
@Component
public final class PasswordHasher {

	private static final Pattern HASH_FORMAT = Pattern.compile(
			"\\$argon2id\\$v=19\\$m=([0-9]{1,6}),t=([0-9]{1,2}),p=([0-9]{1,2})\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}");

	private final PasswordPolicy policy;

	// OWASP Argon2id minimum: 19 MiB, two iterations, one lane.
	private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);

	public PasswordHasher(PasswordPolicy policy) {
		this.policy = policy;
	}

	public String hash(String password, String username) {
		return this.encoder.encode(this.policy.normalizeAndValidate(password, username));
	}

	public boolean matches(String password, String encodedPassword) {
		if (!isSupportedHash(encodedPassword)) {
			return false;
		}
		try {
			return this.encoder.matches(PasswordPolicy.normalize(password), encodedPassword);
		}
		catch (PasswordRejectedException ex) {
			return false;
		}
	}

	private static boolean isSupportedHash(String encodedPassword) {
		if (encodedPassword == null) {
			return false;
		}
		var matcher = HASH_FORMAT.matcher(encodedPassword);
		if (!matcher.matches()) {
			return false;
		}
		int memory = Integer.parseInt(matcher.group(1));
		int iterations = Integer.parseInt(matcher.group(2));
		int parallelism = Integer.parseInt(matcher.group(3));
		// Bound work before passing a stored hash to the cryptographic implementation.
		return parallelism >= 1 && parallelism <= 4 && memory >= 8 * parallelism && memory <= 64 * 1024
				&& iterations >= 1 && iterations <= 10;
	}

}
