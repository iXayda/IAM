package com.ixayda.iam.credential;

import java.time.Instant;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpSensitiveValuesTests {

	@Test
	void protectsAndDestroysCodeAttempts() {
		char[] source = "012345".toCharArray();
		TotpCodeAttempt attempt = new TotpCodeAttempt(source);
		source[0] = '9';

		char[] copy = attempt.copy();
		try {
			assertThat(copy).containsExactly("012345".toCharArray());
			assertThat(attempt.toString()).doesNotContain("012345");
		}
		finally {
			Arrays.fill(copy, '\0');
		}

		attempt.close();
		assertThat(attempt.isDestroyed()).isTrue();
		assertThatThrownBy(attempt::copy).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void rejectsNonAsciiOrMalformedCodeAttempts() {
		assertThatThrownBy(() -> new TotpCodeAttempt("12345".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpCodeAttempt("12345a".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpCodeAttempt("１２３４５６".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void protectsAndDestroysEnrollmentSecrets() {
		byte[] source = secret();
		TotpEnrollment enrollment = new TotpEnrollment(TotpCredentialId.random(),
				Instant.parse("2026-07-20T00:10:00Z"), source);
		source[0] = 0;

		byte[] copy = enrollment.copySecret();
		try {
			assertThat(copy).containsExactly(secret());
			assertThat(enrollment.toString()).contains("secret=redacted").doesNotContain("1, 2, 3");
		}
		finally {
			Arrays.fill(copy, (byte) 0);
		}

		enrollment.close();
		assertThat(enrollment.isDestroyed()).isTrue();
		assertThatThrownBy(enrollment::copySecret).isInstanceOf(IllegalStateException.class);
	}

	private static byte[] secret() {
		byte[] value = new byte[TotpCredential.STANDARD_SECRET_BYTES];
		for (int index = 0; index < value.length; index++) {
			value[index] = (byte) (index + 1);
		}
		return value;
	}

}
