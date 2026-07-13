package com.ixayda.iam.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

class PasswordValuesTests {

	@Test
	void protectsNewPasswordContents() {
		char[] source = "correct horse battery staple".toCharArray();
		NewPassword password = new NewPassword(source);
		Arrays.fill(source, 'x');

		char[] firstCopy = password.copy();
		assertThat(firstCopy).containsExactly("correct horse battery staple".toCharArray());
		Arrays.fill(firstCopy, 'x');

		assertThat(password.copy()).containsExactly("correct horse battery staple".toCharArray());
		assertThat(password.length()).isEqualTo(28);
		assertThat(password.toString()).isEqualTo("NewPassword[redacted]");
		assertThat(password).isNotEqualTo(new NewPassword("correct horse battery staple".toCharArray()));

		password.close();
		password.close();
		assertThat(password.isDestroyed()).isTrue();
		assertThatThrownBy(password::copy).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(password::length).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void validatesNewPasswordPolicy() {
		assertThatThrownBy(() -> new NewPassword(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new NewPassword("short".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new NewPassword("        ".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new NewPassword(new char[NewPassword.MAX_LENGTH + 1]))
			.isInstanceOf(IllegalArgumentException.class);
		assertThat(new NewPassword("12345678".toCharArray()).length()).isEqualTo(NewPassword.MIN_LENGTH);
	}

	@Test
	void protectsPasswordAttemptContentsWithoutApplyingNewPasswordPolicy() {
		char[] source = "old".toCharArray();
		PasswordAttempt attempt = new PasswordAttempt(source);
		Arrays.fill(source, 'x');

		char[] firstCopy = attempt.copy();
		assertThat(firstCopy).containsExactly('o', 'l', 'd');
		Arrays.fill(firstCopy, 'x');

		assertThat(attempt.copy()).containsExactly('o', 'l', 'd');
		assertThat(attempt.length()).isEqualTo(3);
		assertThat(attempt.toString()).isEqualTo("PasswordAttempt[redacted]");
		assertThat(attempt).isNotEqualTo(new PasswordAttempt("old".toCharArray()));

		attempt.destroy();
		attempt.destroy();
		assertThat(attempt.isDestroyed()).isTrue();
		assertThatThrownBy(attempt::copy).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(attempt::length).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void validatesPasswordAttemptInputBounds() {
		assertThatThrownBy(() -> new PasswordAttempt(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new PasswordAttempt(new char[0]))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new PasswordAttempt(new char[PasswordAttempt.MAX_LENGTH + 1]))
			.isInstanceOf(IllegalArgumentException.class);
		assertThat(new PasswordAttempt(new char[] { 'x' }).length()).isOne();
	}

}
