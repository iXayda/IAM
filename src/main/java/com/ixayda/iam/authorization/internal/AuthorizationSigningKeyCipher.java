package com.ixayda.iam.authorization.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
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

final class AuthorizationSigningKeyCipher {

	private static final int INITIALIZATION_VECTOR_BYTES = 12;

	private static final int GCM_TAG_BITS = 128;

	private final String activeKeyId;

	private final Map<String, SecretKeySpec> keys;

	private final SecureRandom random;

	AuthorizationSigningKeyCipher(AuthorizationSigningKeyProtectionProperties properties) {
		this(properties, new SecureRandom());
	}

	AuthorizationSigningKeyCipher(AuthorizationSigningKeyProtectionProperties properties, SecureRandom random) {
		Objects.requireNonNull(properties, "Authorization signing-key protection properties must not be null");
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

	ProtectedPrivateKey protect(byte[] privateKey, KeyContext context) {
		requireConfigured();
		Objects.requireNonNull(privateKey, "Private key material must not be null");
		if (privateKey.length == 0) {
			throw new IllegalArgumentException("Private key material must not be empty");
		}
		byte[] initializationVector = new byte[INITIALIZATION_VECTOR_BYTES];
		this.random.nextBytes(initializationVector);
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, this.keys.get(this.activeKeyId),
					new GCMParameterSpec(GCM_TAG_BITS, initializationVector));
			cipher.updateAAD(context.additionalAuthenticatedData(this.activeKeyId));
			return new ProtectedPrivateKey(this.activeKeyId, initializationVector, cipher.doFinal(privateKey));
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Authorization signing private-key encryption failed", exception);
		}
	}

	byte[] reveal(ProtectedPrivateKey protectedPrivateKey, KeyContext context) {
		Objects.requireNonNull(protectedPrivateKey, "Protected private key must not be null");
		SecretKeySpec key = this.keys.get(protectedPrivateKey.keyId());
		if (key == null) {
			throw new DataRetrievalFailureException(
					"Authorization signing-key protection key is unavailable: " + protectedPrivateKey.keyId());
		}
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key,
					new GCMParameterSpec(GCM_TAG_BITS, protectedPrivateKey.initializationVector()));
			cipher.updateAAD(context.additionalAuthenticatedData(protectedPrivateKey.keyId()));
			return cipher.doFinal(protectedPrivateKey.ciphertext());
		}
		catch (GeneralSecurityException exception) {
			throw new DataRetrievalFailureException("Authorization signing private-key decryption failed", exception);
		}
	}

	private void requireConfigured() {
		if (this.activeKeyId == null) {
			throw new IllegalStateException("Authorization signing-key protection is not configured");
		}
	}

	record KeyContext(UUID signingKeyId, String kid, byte[] publicModulus, int publicExponent) {

		KeyContext {
			Objects.requireNonNull(signingKeyId, "Signing key ID must not be null");
			Objects.requireNonNull(kid, "Signing key kid must not be null");
			publicModulus = Objects.requireNonNull(publicModulus, "Signing key modulus must not be null").clone();
		}

		@Override
		public byte[] publicModulus() {
			return this.publicModulus.clone();
		}

		byte[] additionalAuthenticatedData(String encryptionKeyId) {
			try {
				ByteArrayOutputStream bytes = new ByteArrayOutputStream();
				try (DataOutputStream output = new DataOutputStream(bytes)) {
					output.writeUTF("iam.authorization.signing-private-key");
					output.writeShort(1);
					output.writeUTF(encryptionKeyId);
					output.writeLong(this.signingKeyId.getMostSignificantBits());
					output.writeLong(this.signingKeyId.getLeastSignificantBits());
					output.writeUTF(this.kid);
					output.writeUTF("RSA");
					output.writeUTF("sig");
					output.writeUTF("RS256");
					output.writeInt(this.publicModulus.length);
					output.write(this.publicModulus);
					output.writeInt(this.publicExponent);
					output.writeUTF("PKCS8");
				}
				return bytes.toByteArray();
			}
			catch (IOException exception) {
				throw new IllegalStateException("Authorization signing-key AAD encoding failed", exception);
			}
		}

	}

	record ProtectedPrivateKey(String keyId, byte[] initializationVector, byte[] ciphertext) {

		ProtectedPrivateKey {
			Objects.requireNonNull(keyId, "Protection key ID must not be null");
			initializationVector = Objects.requireNonNull(initializationVector,
					"Initialization vector must not be null").clone();
			ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext must not be null").clone();
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
