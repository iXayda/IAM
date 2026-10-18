package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import org.springframework.stereotype.Component;

/** Single-purpose bearer secrets for completing an already authenticated factor replacement. */
@Component
public final class TotpReplacementTokens {

	private final SecureRandom random = new SecureRandom();

	public String generate() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String digest(UUID userId, UUID replacementId, String token) {
		if (userId == null || replacementId == null || token == null || token.length() != 43
				|| !token.matches("[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")) {
			throw new IllegalArgumentException("Invalid TOTP replacement credential");
		}
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
					("iam:totp-replacement:v1:" + userId + ":" + replacementId + ":" + token).getBytes(StandardCharsets.US_ASCII)));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is unavailable", ex);
		}
	}

}
