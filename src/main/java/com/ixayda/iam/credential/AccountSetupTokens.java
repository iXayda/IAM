package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import org.springframework.stereotype.Component;

/** High-entropy bearer secrets, separated from credentials for other purposes. */
@Component
public final class AccountSetupTokens {

	private final SecureRandom random = new SecureRandom();

	public String generate() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	public String digest(String token) {
		if (token == null || token.length() != 43 || !token.matches("[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")) {
			throw new IllegalArgumentException("Invalid account setup credential");
		}
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(("iam:account-setup:v1:" + token).getBytes(StandardCharsets.US_ASCII)));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is unavailable", ex);
		}
	}

}
