package com.ixayda.iam.credential.internal;

import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.Objects;

import com.ixayda.iam.credential.RecoveryCode;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class RecoveryCodeHashing {

	private static final String DUMMY_CODE = "00000-00000-00000-00000";

	private final PasswordEncoder passwordEncoder;

	private final String dummyEncodedCode;

	RecoveryCodeHashing(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
		this.dummyEncodedCode = passwordEncoder.encode(DUMMY_CODE);
	}

	String encode(RecoveryCode code) {
		Objects.requireNonNull(code, "Recovery code must not be null");
		char[] value = code.copy();
		try {
			return this.passwordEncoder.encode(CharBuffer.wrap(value));
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

	boolean matches(RecoveryCodeAttempt attempt, String encodedCode) {
		Objects.requireNonNull(attempt, "Recovery code attempt must not be null");
		Objects.requireNonNull(encodedCode, "Encoded recovery code must not be null");
		char[] value = attempt.copy();
		try {
			try {
				return this.passwordEncoder.matches(CharBuffer.wrap(value), encodedCode);
			}
			catch (IllegalArgumentException | IndexOutOfBoundsException ex) {
				return false;
			}
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

	void performDummyMatch(RecoveryCodeAttempt attempt) {
		matches(attempt, this.dummyEncodedCode);
	}

}
