package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;

import org.springframework.stereotype.Component;

/** High-entropy, offline recovery secrets; digests are bound to their purpose, owner and factor. */
@Component
public final class MfaRecoveryCodes {

	private final SecureRandom random = new SecureRandom();

	public String generate() {
		byte[] bytes = new byte[16];
		this.random.nextBytes(bytes);
		try {
			String hex = HexFormat.of().formatHex(bytes);
			StringBuilder code = new StringBuilder(39);
			for (int offset = 0; offset < hex.length(); offset += 4) {
				if (offset > 0) { code.append('-'); }
				code.append(hex, offset, offset + 4);
			}
			return code.toString();
		}
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String digest(UUID userId, UUID factorId, String code) {
		if (userId == null || factorId == null || code == null || code.length() != 39
				|| !code.matches("[0-9a-f]{4}(?:-[0-9a-f]{4}){7}")) {
			throw new IllegalArgumentException("Invalid MFA recovery credential");
		}
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
					("iam:mfa-recovery:v1:" + userId + ":" + factorId + ":" + code).getBytes(StandardCharsets.US_ASCII)));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is unavailable", ex);
		}
	}

}
