package com.ixayda.iam.credential.internal;

import java.util.Arrays;

import com.ixayda.iam.credential.RecoveryCode;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RecoveryCodeHashingTests {

	@Test
	void clearsCopiedValuesAfterEncodingAndMatching() {
		CapturingPasswordEncoder encoder = new CapturingPasswordEncoder();
		RecoveryCodeHashing hashing = new RecoveryCodeHashing(encoder);

		try (RecoveryCode code = new RecoveryCode("012AB-CDEFG-HJKMN-PQRST".toCharArray())) {
			assertThat(hashing.encode(code)).isEqualTo("{test}encoded-recovery-code-value-1234567890");
			assertCleared(encoder.captured);
		}
		try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt("012ab-cdefg-hjkmn-pqrst".toCharArray())) {
			assertThat(hashing.matches(attempt, "{test}encoded-recovery-code-value-1234567890")).isTrue();
			assertCleared(encoder.captured);
			hashing.performDummyMatch(attempt);
			assertThat(encoder.matchedEncodedCode).isEqualTo("{test}encoded-recovery-code-value-1234567890");
			assertCleared(encoder.captured);
		}
	}

	@Test
	void failsClosedForMalformedStoredEncodings() {
		PasswordEncoder encoder = new PasswordEncoder() {
			@Override
			public String encode(CharSequence rawPassword) {
				return "{test}encoded-recovery-code-value-1234567890";
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				throw new IllegalArgumentException("malformed");
			}
		};
		RecoveryCodeHashing hashing = new RecoveryCodeHashing(encoder);
		try (RecoveryCodeAttempt attempt = new RecoveryCodeAttempt("012AB-CDEFG-HJKMN-PQRST".toCharArray())) {
			assertThat(hashing.matches(attempt, "{bad}value")).isFalse();
			assertThatThrownBy(() -> hashing.matches(null, "{bad}value"))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> hashing.matches(attempt, null))
				.isInstanceOf(NullPointerException.class);
		}
	}

	private static void assertCleared(CharSequence captured) {
		assertThat(captured).isNotNull();
		assertThat(captured.chars()).allMatch(character -> character == 0);
	}

	private static final class CapturingPasswordEncoder implements PasswordEncoder {

		private CharSequence captured;

		private String matchedEncodedCode;

		@Override
		public String encode(CharSequence rawPassword) {
			this.captured = rawPassword;
			return "{test}encoded-recovery-code-value-1234567890";
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			this.captured = rawPassword;
			this.matchedEncodedCode = encodedPassword;
			return true;
		}

	}

}
