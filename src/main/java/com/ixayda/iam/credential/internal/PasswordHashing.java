package com.ixayda.iam.credential.internal;

import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.Objects;

import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class PasswordHashing {

	private final PasswordEncoder passwordEncoder;

	PasswordHashing(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	String encode(NewPassword password) {
		Objects.requireNonNull(password, "New password must not be null");
		char[] value = password.copy();
		try {
			return this.passwordEncoder.encode(CharBuffer.wrap(value));
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

	String reencode(PasswordAttempt attempt) {
		Objects.requireNonNull(attempt, "Password attempt must not be null");
		char[] value = attempt.copy();
		try {
			return this.passwordEncoder.encode(CharBuffer.wrap(value));
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

	boolean matches(PasswordAttempt attempt, String encodedPassword) {
		Objects.requireNonNull(attempt, "Password attempt must not be null");
		Objects.requireNonNull(encodedPassword, "Encoded password must not be null");
		char[] value = attempt.copy();
		try {
			try {
				return this.passwordEncoder.matches(CharBuffer.wrap(value), encodedPassword);
			}
			catch (IllegalArgumentException | IndexOutOfBoundsException ex) {
				return false;
			}
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

	boolean upgradeEncoding(String encodedPassword) {
		Objects.requireNonNull(encodedPassword, "Encoded password must not be null");
		return this.passwordEncoder.upgradeEncoding(encodedPassword);
	}

}
