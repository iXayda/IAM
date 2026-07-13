package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordHashingTests {

	@Test
	void clearsTheCopiedNewPasswordAfterEncoding() {
		CapturingPasswordEncoder encoder = new CapturingPasswordEncoder();
		PasswordHashing hashing = new PasswordHashing(encoder);

		assertThat(hashing.encode(new NewPassword("correct-password".toCharArray())))
			.isEqualTo("{test}encoded-password-value-1234567890");
		assertCleared(encoder.captured);
	}

	@Test
	void clearsTheCopiedAttemptAfterMatching() {
		CapturingPasswordEncoder encoder = new CapturingPasswordEncoder();
		PasswordHashing hashing = new PasswordHashing(encoder);

		assertThat(hashing.matches(new PasswordAttempt("attempt".toCharArray()),
				"{test}encoded-password-value-1234567890")).isTrue();
		assertCleared(encoder.captured);
	}

	@Test
	void clearsTheCopiedAttemptAfterReencoding() {
		CapturingPasswordEncoder encoder = new CapturingPasswordEncoder();
		PasswordHashing hashing = new PasswordHashing(encoder);

		assertThat(hashing.reencode(new PasswordAttempt("attempt".toCharArray())))
			.isEqualTo("{test}encoded-password-value-1234567890");
		assertCleared(encoder.captured);
	}

	@Test
	void validatesInputsAndDelegatesUpgradeChecks() {
		CapturingPasswordEncoder encoder = new CapturingPasswordEncoder();
		PasswordHashing hashing = new PasswordHashing(encoder);

		assertThatThrownBy(() -> hashing.encode(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> hashing.matches(null, "{test}encoded-password-value-1234567890"))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> hashing.matches(new PasswordAttempt("attempt".toCharArray()), null))
			.isInstanceOf(NullPointerException.class);
		assertThat(hashing.upgradeEncoding("{legacy}encoded-password-value-123456"))
			.isTrue();
		assertThat(encoder.upgradeChecked).isTrue();
	}

	private static void assertCleared(CharSequence captured) {
		assertThat(captured).isNotNull();
		assertThat(captured.chars()).allMatch(character -> character == 0);
	}

	private static final class CapturingPasswordEncoder implements PasswordEncoder {

		private CharSequence captured;

		private boolean upgradeChecked;

		@Override
		public String encode(CharSequence rawPassword) {
			this.captured = rawPassword;
			return "{test}encoded-password-value-1234567890";
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			this.captured = rawPassword;
			return true;
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			this.upgradeChecked = true;
			return true;
		}

	}

}
