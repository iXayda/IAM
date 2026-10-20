package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/** RFC 7636 S256 proof recheck against the exact locked authorization request. */
public final class CodeVerifiers {

	private CodeVerifiers() { }

	public static boolean matchesS256(String verifier, String challenge) {
		if (verifier == null || !verifier.matches("[A-Za-z0-9._~-]{43,128}")
				|| challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")) { return false; }
		try {
			byte[] expected = Base64.getUrlDecoder().decode(challenge);
			if (expected.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(expected).equals(challenge)) { return false; }
			return MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)), expected);
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("S256 proof verification is unavailable"); }
	}

}
