package com.ixayda.iam.credential.internal;

import java.security.SecureRandom;

import com.ixayda.iam.credential.RecoveryCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RecoveryCodeGeneratorTests {

	@Test
	void mapsIndependentRandomSymbolsIntoCanonicalCodes() {
		SecureRandom random = new FixedSecureRandom();
		RecoveryCodeGenerator generator = new RecoveryCodeGenerator(random);

		try (RecoveryCode code = generator.generate()) {
			assertThat(code.copy()).containsExactly("01234-56789-ABCDE-FGHJK".toCharArray());
			assertThat(code.selector()).isEqualTo("01234");
		}
	}

	private static final class FixedSecureRandom extends SecureRandom {

		@Override
		public void nextBytes(byte[] bytes) {
			for (int index = 0; index < bytes.length; index++) {
				bytes[index] = (byte) index;
			}
		}

	}

}
