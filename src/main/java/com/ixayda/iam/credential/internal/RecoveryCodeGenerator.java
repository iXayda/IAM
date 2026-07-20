package com.ixayda.iam.credential.internal;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import com.ixayda.iam.credential.RecoveryCode;

final class RecoveryCodeGenerator {

	private static final char[] ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();

	private static final int GROUP_SIZE = 5;

	private final SecureRandom random;

	RecoveryCodeGenerator() {
		this(new SecureRandom());
	}

	RecoveryCodeGenerator(SecureRandom random) {
		this.random = Objects.requireNonNull(random, "Secure random generator must not be null");
	}

	RecoveryCode generate() {
		byte[] randomBytes = new byte[RecoveryCode.SYMBOL_COUNT];
		char[] value = new char[RecoveryCode.SYMBOL_COUNT + (RecoveryCode.SYMBOL_COUNT / GROUP_SIZE) - 1];
		this.random.nextBytes(randomBytes);
		try {
			int target = 0;
			for (int source = 0; source < randomBytes.length; source++) {
				if (source > 0 && source % GROUP_SIZE == 0) {
					value[target++] = '-';
				}
				value[target++] = ALPHABET[randomBytes[source] & 31];
			}
			return new RecoveryCode(value);
		}
		finally {
			Arrays.fill(randomBytes, (byte) 0);
			Arrays.fill(value, '\0');
		}
	}

}
