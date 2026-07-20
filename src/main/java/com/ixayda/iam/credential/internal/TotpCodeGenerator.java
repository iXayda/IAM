package com.ixayda.iam.credential.internal;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

import javax.crypto.spec.SecretKeySpec;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.ixayda.iam.credential.TotpCredential;

final class TotpCodeGenerator {

	private static final String HMAC_ALGORITHM = TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1;

	private static final long MAX_TIME_STEP = Instant.MAX.getEpochSecond() / TotpCredential.STANDARD_PERIOD_SECONDS;

	private final TimeBasedOneTimePasswordGenerator generator = new TimeBasedOneTimePasswordGenerator(
			Duration.ofSeconds(TotpCredential.STANDARD_PERIOD_SECONDS), TotpCredential.STANDARD_DIGITS, HMAC_ALGORITHM);

	long timeStepAt(Instant instant) {
		Objects.requireNonNull(instant, "TOTP evaluation time must not be null");
		if (instant.getEpochSecond() < 0) {
			throw new IllegalArgumentException("TOTP evaluation time must not precede the Unix epoch");
		}
		return instant.getEpochSecond() / TotpCredential.STANDARD_PERIOD_SECONDS;
	}

	String generate(byte[] secret, long timeStep) {
		requireSecret(secret);
		Instant instant = instantAt(timeStep);
		try {
			return this.generator.generateOneTimePasswordString(new SecretKeySpec(secret, HMAC_ALGORITHM), instant,
					Locale.ROOT);
		}
		catch (InvalidKeyException exception) {
			throw new IllegalStateException("TOTP code generation failed", exception);
		}
	}

	boolean matches(byte[] secret, long timeStep, String candidate) {
		requireSecret(secret);
		Instant instant = instantAt(timeStep);
		if (!isValidCandidate(candidate)) {
			return false;
		}

		byte[] expected = null;
		byte[] actual = candidate.getBytes(StandardCharsets.US_ASCII);
		try {
			expected = this.generator
				.generateOneTimePasswordString(new SecretKeySpec(secret, HMAC_ALGORITHM), instant, Locale.ROOT)
				.getBytes(StandardCharsets.US_ASCII);
			return MessageDigest.isEqual(expected, actual);
		}
		catch (InvalidKeyException exception) {
			throw new IllegalStateException("TOTP code generation failed", exception);
		}
		finally {
			if (expected != null) {
				Arrays.fill(expected, (byte) 0);
			}
			Arrays.fill(actual, (byte) 0);
		}
	}

	private static Instant instantAt(long timeStep) {
		if (timeStep < 0 || timeStep > MAX_TIME_STEP) {
			throw new IllegalArgumentException("TOTP time step is outside the supported range");
		}
		return Instant.ofEpochSecond(timeStep * TotpCredential.STANDARD_PERIOD_SECONDS);
	}

	private static void requireSecret(byte[] secret) {
		Objects.requireNonNull(secret, "TOTP secret must not be null");
		if (secret.length != TotpSecretCipher.SECRET_BYTES) {
			throw new IllegalArgumentException("TOTP secret must contain exactly 20 bytes");
		}
	}

	private static boolean isValidCandidate(String candidate) {
		if (candidate == null || candidate.length() != TotpCredential.STANDARD_DIGITS) {
			return false;
		}
		return candidate.chars().allMatch(character -> character >= '0' && character <= '9');
	}

}
