package com.ixayda.iam.client.internal;

import java.nio.CharBuffer;
import java.util.Arrays;
import java.util.Objects;

import com.ixayda.iam.client.IssuedClientSecret;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class ClientSecretHashing {

	private final PasswordEncoder passwordEncoder;

	ClientSecretHashing(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	String encode(IssuedClientSecret secret) {
		Objects.requireNonNull(secret, "Issued client secret must not be null");
		char[] value = secret.copy();
		try {
			return this.passwordEncoder.encode(CharBuffer.wrap(value));
		}
		finally {
			Arrays.fill(value, '\0');
		}
	}

}
