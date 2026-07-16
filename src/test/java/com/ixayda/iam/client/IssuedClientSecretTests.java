package com.ixayda.iam.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

class IssuedClientSecretTests {

	@Test
	void generatesA256BitUrlSafeSecretWithoutDiagnosticDisclosure() {
		try (IssuedClientSecret secret = IssuedClientSecret.generate()) {
			char[] value = secret.copy();
			try {
				assertThat(value).hasSize(43);
				assertThat(new String(value)).matches("[A-Za-z0-9_-]{43}");
				assertThat(secret.toString()).isEqualTo("[PROTECTED]");
			}
			finally {
				Arrays.fill(value, '\0');
			}
		}
	}

	@Test
	void destroysItsSecretMaterialIdempotently() {
		IssuedClientSecret secret = IssuedClientSecret.generate();

		secret.close();
		secret.close();

		assertThat(secret.isDestroyed()).isTrue();
		assertThatThrownBy(secret::copy).isInstanceOf(IllegalStateException.class)
			.hasMessage("Client secret has been destroyed");
	}

}
