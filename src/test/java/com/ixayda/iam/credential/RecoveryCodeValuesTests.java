package com.ixayda.iam.credential;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RecoveryCodeValuesTests {

	@Test
	void protectsGeneratedCodeContents() {
		char[] source = "012AB-CDEFG-HJKMN-PQRST".toCharArray();
		RecoveryCode code = new RecoveryCode(source);
		Arrays.fill(source, 'X');

		char[] copy = code.copy();
		try {
			assertThat(copy).containsExactly("012AB-CDEFG-HJKMN-PQRST".toCharArray());
			assertThat(code.selector()).isEqualTo("012AB");
			assertThat(code.toString()).isEqualTo("RecoveryCode[redacted]");
		}
		finally {
			Arrays.fill(copy, '\0');
		}

		code.close();
		code.close();
		assertThat(code.isDestroyed()).isTrue();
		assertThatThrownBy(code::copy).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(code::selector).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void normalizesAttemptsWithoutAcceptingAmbiguousSymbols() {
		try (RecoveryCodeAttempt formatted = new RecoveryCodeAttempt("012ab-cdefg-hjkmn-pqrst".toCharArray());
				RecoveryCodeAttempt compact = new RecoveryCodeAttempt("012ABCDEFGHJKMNPQRST".toCharArray())) {
			assertThat(formatted.copy()).containsExactly("012AB-CDEFG-HJKMN-PQRST".toCharArray());
			assertThat(compact.copy()).containsExactly("012AB-CDEFG-HJKMN-PQRST".toCharArray());
			assertThat(formatted.selector()).isEqualTo("012AB");
			assertThat(formatted.toString()).isEqualTo("RecoveryCodeAttempt[redacted]");
		}

		assertThatThrownBy(() -> new RecoveryCode("012ab-CDEFG-HJKMN-PQRST".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new RecoveryCodeAttempt("O12AB-CDEFG-HJKMN-PQRST".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new RecoveryCodeAttempt("012AB_CDEFG_HJKMN_PQRST".toCharArray()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new RecoveryCodeAttempt(new char[0]))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
