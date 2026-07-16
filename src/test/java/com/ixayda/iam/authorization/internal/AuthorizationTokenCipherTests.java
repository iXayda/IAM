package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataRetrievalFailureException;

class AuthorizationTokenCipherTests {

	private static final String KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	private static final AuthorizationTokenCipher.TokenContext CONTEXT =
			new AuthorizationTokenCipher.TokenContext(
					UUID.fromString("019cbe4d-cd53-7f1f-987e-ce0cb7f9e001"),
					UUID.fromString("019cbe4d-cd53-7f1f-987e-ce0cb7f9e002"),
					UUID.fromString("019cbe4d-cd53-7f1f-987e-ce0cb7f9e003"),
					UUID.fromString("019cbe4d-cd53-7f1f-987e-ce0cb7f9e004"), "authorization_code");

	@Test
	void protectsAndRevealsTokensBoundToTheirDatabaseIdentity() {
		AuthorizationTokenCipher cipher = cipher("v1", Map.of("v1", KEY));

		AuthorizationTokenCipher.ProtectedToken protectedToken = cipher.protect("opaque-token", CONTEXT);

		assertThat(protectedToken.keyId()).isEqualTo("v1");
		assertThat(protectedToken.digest()).hasSize(32);
		assertThat(protectedToken.initializationVector()).hasSize(12);
		assertThat(protectedToken.ciphertext()).doesNotContain("opaque-token".getBytes());
		assertThat(cipher.reveal(protectedToken, CONTEXT)).isEqualTo("opaque-token");
		assertThat(cipher.digest("opaque-token")).containsExactly(protectedToken.digest());
	}

	@Test
	void rejectsAProtectedTokenUnderDifferentAdditionalAuthenticatedData() {
		AuthorizationTokenCipher cipher = cipher("v1", Map.of("v1", KEY));
		AuthorizationTokenCipher.ProtectedToken protectedToken = cipher.protect("opaque-token", CONTEXT);
		AuthorizationTokenCipher.TokenContext differentContext = new AuthorizationTokenCipher.TokenContext(
				CONTEXT.tenantId(), CONTEXT.clientId(), CONTEXT.authorizationId(), UUID.randomUUID(), CONTEXT.tokenType());

		assertThatThrownBy(() -> cipher.reveal(protectedToken, differentContext))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization token decryption failed");
	}

	@Test
	void failsClosedWhenProtectionIsNotConfiguredOrAnOldKeyIsUnavailable() {
		AuthorizationTokenCipher unconfigured = cipher("", Map.of("v1", ""));
		assertThatThrownBy(() -> unconfigured.protect("opaque-token", CONTEXT))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Authorization token protection is not configured");

		AuthorizationTokenCipher original = cipher("v1", Map.of("v1", KEY));
		AuthorizationTokenCipher.ProtectedToken protectedToken = original.protect("opaque-token", CONTEXT);
		AuthorizationTokenCipher rotated = cipher("v2", Map.of("v2", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="));
		assertThatThrownBy(() -> rotated.reveal(protectedToken, CONTEXT))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization token protection key is unavailable: v1");
	}

	private static AuthorizationTokenCipher cipher(String activeKeyId, Map<String, String> keys) {
		return new AuthorizationTokenCipher(new AuthorizationTokenProtectionProperties(activeKeyId, keys),
				new FixedSecureRandom());
	}

	private static final class FixedSecureRandom extends SecureRandom {

		@Override
		public void nextBytes(byte[] bytes) {
			for (int index = 0; index < bytes.length; index++) {
				bytes[index] = (byte) (index + 1);
			}
		}

	}

}
