package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;

class AuthorizationPersistencePropertiesTests {

	private static final String KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	@Test
	void acceptsBoundedPersistenceDurations() {
		AuthorizationPersistenceProperties properties =
				new AuthorizationPersistenceProperties(Duration.ofMinutes(10), Duration.ofDays(1));

		assertThat(properties.pendingAuthorizationTtl()).isEqualTo(Duration.ofMinutes(10));
		assertThat(properties.tokenRetention()).isEqualTo(Duration.ofDays(1));
	}

	@Test
	void rejectsUnboundedPersistenceDurations() {
		assertThatThrownBy(() -> new AuthorizationPersistenceProperties(Duration.ZERO, Duration.ofDays(1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationPersistenceProperties(Duration.ofMinutes(31), Duration.ofDays(1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AuthorizationPersistenceProperties(Duration.ofMinutes(10), Duration.ofDays(31)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void supportsAnUnconfiguredKeyRingWithoutExposingKeys() {
		AuthorizationTokenProtectionProperties properties =
				new AuthorizationTokenProtectionProperties("", Map.of("v1", ""));

		assertThat(properties.isConfigured()).isFalse();
		assertThat(properties.keys()).isEmpty();
		assertThat(properties.toString()).contains("configuredKeyCount=0", "keys=redacted").doesNotContain(KEY);
	}

	@Test
	void validatesTheActiveKeyRing() {
		AuthorizationTokenProtectionProperties properties =
				new AuthorizationTokenProtectionProperties("v1", Map.of("v1", KEY));

		assertThat(properties.isConfigured()).isTrue();
		assertThat(properties.decodedKeys().get("v1")).hasSize(32);
		assertThatThrownBy(() -> new AuthorizationTokenProtectionProperties("v2", Map.of("v1", KEY)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("The active authorization token protection key is not configured");
		assertThatThrownBy(() -> new AuthorizationTokenProtectionProperties("v1", Map.of("v1", "not-base64")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("must be valid Base64");
		assertThatThrownBy(() -> new AuthorizationTokenProtectionProperties("v1",
				Map.of("v1", "AAAAAAAAAAAAAAAAAAAAAA==")))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("exactly 32 bytes");
	}

}
