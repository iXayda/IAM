package com.ixayda.iam.authorization.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.dao.DataRetrievalFailureException;

final class AuthorizationTokenCipher {

	private static final int INITIALIZATION_VECTOR_BYTES = 12;

	private static final int GCM_TAG_BITS = 128;

	private final String activeKeyId;

	private final Map<String, SecretKeySpec> keys;

	private final SecureRandom random;

	AuthorizationTokenCipher(AuthorizationTokenProtectionProperties properties) {
		this(properties, new SecureRandom());
	}

	AuthorizationTokenCipher(AuthorizationTokenProtectionProperties properties, SecureRandom random) {
		Objects.requireNonNull(properties, "Authorization token protection properties must not be null");
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

	ProtectedToken protect(String tokenValue, TokenContext context) {
		requireConfigured();
		Objects.requireNonNull(tokenValue, "Token value must not be null");
		if (tokenValue.isEmpty()) {
			throw new IllegalArgumentException("Token value must not be empty");
		}
		byte[] plaintext = tokenValue.getBytes(StandardCharsets.UTF_8);
		byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTES];
		this.random.nextBytes(initializationVector);
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, this.keys.get(this.activeKeyId),
					new GCMParameterSpec(GCM_TAG_BITS, initializationVector));
			cipher.updateAAD(context.additionalAuthenticatedData());
			return new ProtectedToken(digest(tokenValue), this.activeKeyId, initializationVector,
					cipher.doFinal(plaintext));
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Authorization token encryption failed", exception);
		}
		finally {
			Arrays.fill(plaintext, (byte) 0);
		}
	}

	String reveal(ProtectedToken protectedToken, TokenContext context) {
		Objects.requireNonNull(protectedToken, "Protected token must not be null");
		SecretKeySpec key = this.keys.get(protectedToken.keyId());
		if (key == null) {
			throw new DataRetrievalFailureException(
					"Authorization token protection key is unavailable: " + protectedToken.keyId());
		}
		byte[] plaintext = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key,
					new GCMParameterSpec(GCM_TAG_BITS, protectedToken.initializationVector()));
			cipher.updateAAD(context.additionalAuthenticatedData());
			plaintext = cipher.doFinal(protectedToken.ciphertext());
			String tokenValue = new String(plaintext, StandardCharsets.UTF_8);
			if (!MessageDigest.isEqual(protectedToken.digest(), digest(tokenValue))) {
				throw new DataRetrievalFailureException("Authorization token digest validation failed");
			}
			return tokenValue;
		}
		catch (DataRetrievalFailureException exception) {
			throw exception;
		}
		catch (GeneralSecurityException exception) {
			throw new DataRetrievalFailureException("Authorization token decryption failed", exception);
		}
		finally {
			if (plaintext != null) {
				Arrays.fill(plaintext, (byte) 0);
			}
		}
	}

	byte[] digest(String tokenValue) {
		Objects.requireNonNull(tokenValue, "Token value must not be null");
		try {
			return MessageDigest.getInstance("SHA-256").digest(tokenValue.getBytes(StandardCharsets.UTF_8));
		}
		catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("SHA-256 is unavailable", exception);
		}
	}

	private void requireConfigured() {
		if (this.activeKeyId == null) {
			throw new IllegalStateException("Authorization token protection is not configured");
		}
	}

	record TokenContext(UUID tenantId, UUID clientId, UUID authorizationId, UUID tokenId, String tokenType) {

		TokenContext {
			Objects.requireNonNull(tenantId, "Tenant ID must not be null");
			Objects.requireNonNull(clientId, "Client ID must not be null");
			Objects.requireNonNull(authorizationId, "Authorization ID must not be null");
			Objects.requireNonNull(tokenId, "Token ID must not be null");
			Objects.requireNonNull(tokenType, "Token type must not be null");
		}

		byte[] additionalAuthenticatedData() {
			return String.join("\n", this.tenantId.toString(), this.clientId.toString(),
					this.authorizationId.toString(), this.tokenId.toString(), this.tokenType)
				.getBytes(StandardCharsets.US_ASCII);
		}

	}

	record ProtectedToken(byte[] digest, String keyId, byte[] initializationVector, byte[] ciphertext) {

		ProtectedToken {
			digest = digest.clone();
			initializationVector = initializationVector.clone();
			ciphertext = ciphertext.clone();
		}

		@Override
		public byte[] digest() {
			return this.digest.clone();
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
