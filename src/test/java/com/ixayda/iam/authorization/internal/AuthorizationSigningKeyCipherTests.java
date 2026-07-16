package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataRetrievalFailureException;

class AuthorizationSigningKeyCipherTests {

	private static final String KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

	private static final AuthorizationSigningKeyCipher.KeyContext CONTEXT =
			new AuthorizationSigningKeyCipher.KeyContext(
					UUID.fromString("019cf2eb-c956-75e2-9cf1-9042aaa92001"), "A".repeat(43), modulus(), 65537);

	@Test
	void protectsPrivateKeysBoundToTheirStableIdentity() {
		AuthorizationSigningKeyCipher cipher = cipher("v1", Map.of("v1", KEY));
		byte[] privateKey = "private-key-material".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

		AuthorizationSigningKeyCipher.ProtectedPrivateKey protectedKey = cipher.protect(privateKey, CONTEXT);

		assertThat(protectedKey.keyId()).isEqualTo("v1");
		assertThat(protectedKey.initializationVector()).hasSize(12);
		assertThat(protectedKey.ciphertext()).isNotEqualTo(privateKey).hasSizeGreaterThan(privateKey.length);
		assertThat(cipher.reveal(protectedKey, CONTEXT)).containsExactly(privateKey);
	}

	@Test
	void rejectsChangedIdentityCiphertextAndUnavailableKeys() {
		AuthorizationSigningKeyCipher cipher = cipher("v1", Map.of("v1", KEY));
		AuthorizationSigningKeyCipher.ProtectedPrivateKey protectedKey =
				cipher.protect(new byte[] { 1, 2, 3 }, CONTEXT);
		AuthorizationSigningKeyCipher.KeyContext changed = new AuthorizationSigningKeyCipher.KeyContext(
				UUID.randomUUID(), CONTEXT.kid(), CONTEXT.publicModulus(), CONTEXT.publicExponent());

		assertThatThrownBy(() -> cipher.reveal(protectedKey, changed))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing private-key decryption failed");
		byte[] changedCiphertext = protectedKey.ciphertext();
		changedCiphertext[0] ^= 1;
		AuthorizationSigningKeyCipher.ProtectedPrivateKey corrupted = new AuthorizationSigningKeyCipher.ProtectedPrivateKey(
				protectedKey.keyId(), protectedKey.initializationVector(), changedCiphertext);
		assertThatThrownBy(() -> cipher.reveal(corrupted, CONTEXT))
			.isInstanceOf(DataRetrievalFailureException.class);

		AuthorizationSigningKeyCipher rotated = cipher("v2",
				Map.of("v2", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="));
		assertThatThrownBy(() -> rotated.reveal(protectedKey, CONTEXT))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("Authorization signing-key protection key is unavailable: v1");
	}

	@Test
	void failsClosedWithoutAProtectionKey() {
		AuthorizationSigningKeyCipher cipher = cipher("", Map.of("v1", ""));

		assertThatThrownBy(() -> cipher.protect(new byte[] { 1 }, CONTEXT))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("Authorization signing-key protection is not configured");
	}

	private static AuthorizationSigningKeyCipher cipher(String activeKeyId, Map<String, String> keys) {
		return new AuthorizationSigningKeyCipher(
				new AuthorizationSigningKeyProtectionProperties(activeKeyId, keys), new FixedSecureRandom());
	}

	private static byte[] modulus() {
		byte[] modulus = new byte[384];
		Arrays.fill(modulus, (byte) 3);
		modulus[0] = (byte) 0x80;
		return modulus;
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
