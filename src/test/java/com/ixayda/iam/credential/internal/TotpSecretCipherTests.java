package com.ixayda.iam.credential.internal;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

import com.ixayda.iam.credential.TotpAlgorithm;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataRetrievalFailureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpSecretCipherTests {

	private static final String FIRST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	private static final String SECOND_KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

	private static final TotpSecretCipher.SecretContext CONTEXT = new TotpSecretCipher.SecretContext(
			TenantId.DEFAULT, UserId.from("019f5aff-f979-7653-8001-67ea4274f301"),
			TotpCredentialId.from("019f5aff-f979-7653-8001-67ea4274f302"), TotpAlgorithm.SHA1, 6, 30);

	@Test
	void protectsAndRevealsAStandardSecretBoundToCredentialIdentity() {
		TotpSecretCipher cipher = cipher("v1", Map.of("v1", FIRST_KEY));
		byte[] secret = secret();

		TotpSecretCipher.ProtectedTotpSecret protectedSecret = cipher.protect(secret, CONTEXT);
		byte[] revealed = cipher.reveal(protectedSecret, CONTEXT);

		try {
			assertThat(protectedSecret.protectionVersion()).isOne();
			assertThat(protectedSecret.keyId()).isEqualTo("v1");
			assertThat(protectedSecret.initializationVector()).hasSize(12);
			assertThat(protectedSecret.ciphertext()).hasSize(36).isNotEqualTo(secret);
			assertThat(revealed).containsExactly(secret);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
			Arrays.fill(revealed, (byte) 0);
		}
	}

	@Test
	void rejectsDifferentAdditionalAuthenticatedDataAndTampering() {
		TotpSecretCipher cipher = cipher("v1", Map.of("v1", FIRST_KEY));
		byte[] secret = secret();
		TotpSecretCipher.ProtectedTotpSecret protectedSecret;
		try {
			protectedSecret = cipher.protect(secret, CONTEXT);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
		TotpSecretCipher.SecretContext differentContext = new TotpSecretCipher.SecretContext(TenantId.random(),
				CONTEXT.userId(), CONTEXT.credentialId(), CONTEXT.algorithm(), CONTEXT.digits(), CONTEXT.periodSeconds());
		byte[] tamperedCiphertext = protectedSecret.ciphertext();
		tamperedCiphertext[0] ^= 1;
		TotpSecretCipher.ProtectedTotpSecret tampered = new TotpSecretCipher.ProtectedTotpSecret(
				protectedSecret.protectionVersion(), protectedSecret.keyId(), protectedSecret.initializationVector(),
				tamperedCiphertext);

		assertThatThrownBy(() -> cipher.reveal(protectedSecret, differentContext))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("TOTP secret decryption failed");
		assertThatThrownBy(() -> cipher.reveal(tampered, CONTEXT))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("TOTP secret decryption failed");
	}

	@Test
	void rotatesWritesWhileRetainingConfiguredReadKeys() {
		TotpSecretCipher original = cipher("v1", Map.of("v1", FIRST_KEY));
		byte[] secret = secret();
		TotpSecretCipher.ProtectedTotpSecret protectedSecret;
		try {
			protectedSecret = original.protect(secret, CONTEXT);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
		TotpSecretCipher rotated = cipher("v2", Map.of("v1", FIRST_KEY, "v2", SECOND_KEY));
		byte[] revealed = rotated.reveal(protectedSecret, CONTEXT);
		try {
			assertThat(revealed).containsExactly(secret());
			assertThat(rotated.protect(secret(), CONTEXT).keyId()).isEqualTo("v2");
		}
		finally {
			Arrays.fill(revealed, (byte) 0);
		}
	}

	@Test
	void failsClosedWithoutAnActiveOrHistoricalKey() {
		TotpSecretCipher unconfigured = cipher("", Map.of("v1", ""));
		byte[] secret = secret();
		try {
			assertThatThrownBy(() -> unconfigured.protect(secret, CONTEXT))
				.isInstanceOf(IllegalStateException.class)
				.hasMessage("TOTP secret protection is not configured");
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}

		TotpSecretCipher original = cipher("v1", Map.of("v1", FIRST_KEY));
		byte[] originalSecret = secret();
		TotpSecretCipher.ProtectedTotpSecret protectedSecret;
		try {
			protectedSecret = original.protect(originalSecret, CONTEXT);
		}
		finally {
			Arrays.fill(originalSecret, (byte) 0);
		}
		TotpSecretCipher missingOldKey = cipher("v2", Map.of("v2", SECOND_KEY));
		assertThatThrownBy(() -> missingOldKey.reveal(protectedSecret, CONTEXT))
			.isInstanceOf(DataRetrievalFailureException.class)
			.hasMessage("TOTP secret protection key is unavailable: v1");
	}

	@Test
	void validatesProtectionConfigurationWithoutExposingKeys() {
		assertThatThrownBy(() -> new TotpSecretProtectionProperties("v1", Map.of("v1", "not-base64")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSecretProtectionProperties("v1", Map.of("v1", "AQ==")))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSecretProtectionProperties("v2", Map.of("v1", FIRST_KEY)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpSecretProtectionProperties("v1",
				Map.of("v1", FIRST_KEY, "duplicate", FIRST_KEY)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("TOTP secret protection keys must use distinct key material");
		assertThat(new TotpSecretProtectionProperties("v1", Map.of("v1", FIRST_KEY)).toString())
			.doesNotContain(FIRST_KEY)
			.contains("keys=redacted");
	}

	private static TotpSecretCipher cipher(String activeKeyId, Map<String, String> keys) {
		return new TotpSecretCipher(new TotpSecretProtectionProperties(activeKeyId, keys), new FixedSecureRandom());
	}

	private static byte[] secret() {
		byte[] secret = new byte[TotpSecretCipher.SECRET_BYTES];
		for (int index = 0; index < secret.length; index++) {
			secret[index] = (byte) (index + 1);
		}
		return secret;
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
