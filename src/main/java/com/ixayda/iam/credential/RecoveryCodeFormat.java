package com.ixayda.iam.credential;

import java.util.Arrays;
import java.util.Objects;

final class RecoveryCodeFormat {

	static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

	static final int SYMBOL_COUNT = 20;

	static final int GROUP_SIZE = 5;

	static final int SELECTOR_LENGTH = GROUP_SIZE;

	static final int FORMATTED_LENGTH = SYMBOL_COUNT + (SYMBOL_COUNT / GROUP_SIZE) - 1;

	private RecoveryCodeFormat() {
	}

	static char[] requireCanonical(char[] value) {
		Objects.requireNonNull(value, "Recovery code must not be null");
		if (value.length != FORMATTED_LENGTH) {
			throw invalid();
		}
		for (int index = 0; index < value.length; index++) {
			boolean separator = (index + 1) % (GROUP_SIZE + 1) == 0;
			if (separator ? value[index] != '-' : ALPHABET.indexOf(value[index]) < 0) {
				throw invalid();
			}
		}
		return value.clone();
	}

	static char[] normalizeAttempt(char[] value) {
		Objects.requireNonNull(value, "Recovery code attempt must not be null");
		if (value.length != SYMBOL_COUNT && value.length != FORMATTED_LENGTH) {
			throw invalid();
		}
		char[] normalized = new char[FORMATTED_LENGTH];
		try {
			int source = 0;
			for (int target = 0; target < normalized.length; target++) {
				if ((target + 1) % (GROUP_SIZE + 1) == 0) {
					normalized[target] = '-';
					if (value.length == FORMATTED_LENGTH && value[source++] != '-') {
						throw invalid();
					}
					continue;
				}
				char symbol = Character.toUpperCase(value[source++]);
				if (ALPHABET.indexOf(symbol) < 0) {
					throw invalid();
				}
				normalized[target] = symbol;
			}
			return normalized;
		}
		catch (RuntimeException ex) {
			Arrays.fill(normalized, '\0');
			throw ex;
		}
	}

	static String selector(char[] canonical) {
		return new String(canonical, 0, SELECTOR_LENGTH);
	}

	private static IllegalArgumentException invalid() {
		return new IllegalArgumentException(
				"Recovery code must contain four groups of five unambiguous Base32 symbols");
	}

}
