package com.ixayda.iam.credential.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ixayda.iam.credential.TotpAlgorithm;
import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.dao.DataRetrievalFailureException;

final class TotpSecretCipher {

	static final int SECRET_BYTES = TotpCredential.STANDARD_SECRET_BYTES;

	private static final int INITIALIZATION_VECTOR_BYTES = 12;

	private static final int GCM_TAG_BITS = 128;

	private static final int PROTECTION_VERSION = 1;

	private static final String PROTECTION_PURPOSE = "iam.totp-secret";

	private final String activeKeyId;

	private final Map<String, SecretKeySpec> keys;

	private final SecureRandom random;

	TotpSecretCipher(TotpSecretProtectionProperties properties) {
		this(properties, new SecureRandom());
	}

	TotpSecretCipher(TotpSecretProtectionProperties properties, SecureRandom random) {
		Objects.requireNonNull(properties, "TOTP secret protection properties must not be null");
		this.activeKeyId = properties.activeKeyId();
		this.random = Objects.requireNonNull(random, "Secure random generator must not be null");
		Map<String, byte[]> decodedKeys = properties.decodedKeys();
		Map<String, SecretKeySpec> configuredKeys = new LinkedHashMap<>();
		try {
			decodedKeys.forEach((keyId, key) -> configuredKeys.put(keyId, new SecretKeySpec(key, "AES")));
		}
		finally {
			decodedKeys.values().forEach(key -> Arrays.fill(key, (byte) 0));
		}
		this.keys = Map.copyOf(configuredKeys);
	}

	/**
	 * Protects caller-owned secret bytes. This method never retains or clears the input.
	 */
	ProtectedTotpSecret protect(byte[] secret, SecretContext context) {
		requireConfigured();
		requireSecret(secret);
		Objects.requireNonNull(context, "TOTP secret context must not be null");
		byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTES];
		this.random.nextBytes(initializationVector);
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, this.keys.get(this.activeKeyId),
					new GCMParameterSpec(GCM_TAG_BITS, initializationVector));
			cipher.updateAAD(context.additionalAuthenticatedData(PROTECTION_VERSION, this.activeKeyId));
			return new ProtectedTotpSecret(PROTECTION_VERSION, this.activeKeyId, initializationVector,
					cipher.doFinal(secret));
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("TOTP secret encryption failed", exception);
		}
	}

	/**
	 * Returns newly allocated plaintext bytes. The caller must clear the returned array in
	 * a {@code finally} block.
	 */
	byte[] reveal(ProtectedTotpSecret protectedSecret, SecretContext context) {
		Objects.requireNonNull(protectedSecret, "Protected TOTP secret must not be null");
		Objects.requireNonNull(context, "TOTP secret context must not be null");
		if (protectedSecret.protectionVersion() != PROTECTION_VERSION) {
			throw new DataRetrievalFailureException(
					"TOTP secret protection version is unsupported: " + protectedSecret.protectionVersion());
		}
		SecretKeySpec key = this.keys.get(protectedSecret.keyId());
		if (key == null) {
			throw new DataRetrievalFailureException(
					"TOTP secret protection key is unavailable: " + protectedSecret.keyId());
		}
		byte[] plaintext = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key,
					new GCMParameterSpec(GCM_TAG_BITS, protectedSecret.initializationVector()));
			cipher.updateAAD(context.additionalAuthenticatedData(protectedSecret.protectionVersion(),
					protectedSecret.keyId()));
			plaintext = cipher.doFinal(protectedSecret.ciphertext());
			if (plaintext.length != SECRET_BYTES) {
				throw new DataRetrievalFailureException("Decrypted TOTP secret has an invalid length");
			}
			byte[] result = plaintext;
			plaintext = null;
			return result;
		}
		catch (DataRetrievalFailureException exception) {
			throw exception;
		}
		catch (GeneralSecurityException exception) {
			throw new DataRetrievalFailureException("TOTP secret decryption failed", exception);
		}
		finally {
			if (plaintext != null) {
				Arrays.fill(plaintext, (byte) 0);
			}
		}
	}

	private static void requireSecret(byte[] secret) {
		Objects.requireNonNull(secret, "TOTP secret must not be null");
		if (secret.length != SECRET_BYTES) {
			throw new IllegalArgumentException("TOTP secret must contain exactly 20 bytes");
		}
	}

	private void requireConfigured() {
		if (this.activeKeyId == null) {
			throw new IllegalStateException("TOTP secret protection is not configured");
		}
	}

	record SecretContext(TenantId tenantId, UserId userId, TotpCredentialId credentialId,
			TotpAlgorithm algorithm, int digits, int periodSeconds) {

		SecretContext {
			Objects.requireNonNull(tenantId, "TOTP secret tenant ID must not be null");
			Objects.requireNonNull(userId, "TOTP secret user ID must not be null");
			Objects.requireNonNull(credentialId, "TOTP secret credential ID must not be null");
			Objects.requireNonNull(algorithm, "TOTP secret algorithm must not be null");
			if (digits <= 0 || periodSeconds <= 0) {
				throw new IllegalArgumentException("TOTP secret parameters must be positive");
			}
		}

		byte[] additionalAuthenticatedData(int protectionVersion, String keyId) {
			if (protectionVersion <= 0) {
				throw new IllegalArgumentException("TOTP secret protection version must be positive");
			}
			Objects.requireNonNull(keyId, "TOTP secret protection key ID must not be null");
			return String.join("\n", PROTECTION_PURPOSE, Integer.toString(protectionVersion), keyId,
					this.tenantId.toString(), this.userId.toString(), this.credentialId.toString(),
					this.algorithm.name(), Integer.toString(this.digits), Integer.toString(this.periodSeconds))
				.getBytes(StandardCharsets.US_ASCII);
		}

	}

	record ProtectedTotpSecret(int protectionVersion, String keyId, byte[] initializationVector, byte[] ciphertext) {

		ProtectedTotpSecret {
			if (protectionVersion <= 0) {
				throw new IllegalArgumentException("TOTP secret protection version must be positive");
			}
			Objects.requireNonNull(keyId, "TOTP secret protection key ID must not be null");
			Objects.requireNonNull(initializationVector, "TOTP secret initialization vector must not be null");
			Objects.requireNonNull(ciphertext, "TOTP secret ciphertext must not be null");
			initializationVector = initializationVector.clone();
			ciphertext = ciphertext.clone();
		}

		@Override
		public byte[] initializationVector() {
			return this.initializationVector.clone();
		}

		@Override
		public byte[] ciphertext() {
			return this.ciphertext.clone();
		}

	}

}
