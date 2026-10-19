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

/** A deployment recovery proof cannot be used by the ordinary TOTP recovery workflow. */
@Component
public final class AdministratorRecoveryTokens {

	private final SecureRandom random = new SecureRandom();

	public String generate() {
		byte[] bytes = new byte[32];
		this.random.nextBytes(bytes);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String digest(UUID userId, UUID recoveryId, String token) {
		return digest("iam:administrator-recovery:v1:", userId, recoveryId, token);
	}

	public String credentialRecoveryDigest(UUID userId, UUID recoveryId, String token) {
		return digest("iam:administrator-credential-recovery:v1:", userId, recoveryId, token);
	}

	private String digest(String purpose, UUID userId, UUID recoveryId, String token) {
		if (userId == null || recoveryId == null || token == null || token.length() != 43
				|| !token.matches("[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")) {
			throw new IllegalArgumentException("Invalid administrator recovery credential");
		}
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
					(purpose + userId + ":" + recoveryId + ":" + token).getBytes(StandardCharsets.US_ASCII)));
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 is unavailable", ex); }
	}

}
