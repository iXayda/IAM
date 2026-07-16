package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;

import org.junit.jupiter.api.Test;

class AuthorizationSigningKeyProtectionPropertiesTests {

	private static final String KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

	@Test
	void supportsAnUnconfiguredKeyRingWithoutExposingKeys() {
		AuthorizationSigningKeyProtectionProperties properties =
				new AuthorizationSigningKeyProtectionProperties("", Map.of("v1", ""));

		assertThat(properties.isConfigured()).isFalse();
		assertThat(properties.keys()).isEmpty();
		assertThat(properties.toString()).contains("configuredKeyCount=0", "keys=redacted").doesNotContain(KEY);
	}

	@Test
	void validatesAndRedactsTheActiveKeyRing() {
		AuthorizationSigningKeyProtectionProperties properties =
				new AuthorizationSigningKeyProtectionProperties("v1", Map.of("v1", KEY));

		assertThat(properties.isConfigured()).isTrue();
		assertThat(properties.decodedKeys().get("v1")).hasSize(32);
		assertThat(properties.toString()).contains("activeKeyId=v1", "keys=redacted").doesNotContain(KEY);
		assertThatThrownBy(() -> new AuthorizationSigningKeyProtectionProperties("v2", Map.of("v1", KEY)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("The active authorization signing-key protection key is not configured");
		assertThatThrownBy(() -> new AuthorizationSigningKeyProtectionProperties("v1", Map.of("v1", "not-base64!")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("valid Base64");
		assertThatThrownBy(() -> new AuthorizationSigningKeyProtectionProperties("v1",
				Map.of("v1", "AAAAAAAAAAAAAAAAAAAAAA==")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("exactly 32 bytes");
	}

}
