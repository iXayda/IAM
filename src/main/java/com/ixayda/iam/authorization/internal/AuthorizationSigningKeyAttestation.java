package com.ixayda.iam.authorization.internal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.dao.DataRetrievalFailureException;

final class AuthorizationSigningKeyAttestation {

	private static final int VERSION = 1;

	private static final byte[] DERIVATION_LABEL =
			"iam.authorization.signing-key.attestation.v1".getBytes(StandardCharsets.US_ASCII);

	private final String activeKeyId;

	private final Map<String, SecretKeySpec> keys;

	AuthorizationSigningKeyAttestation(AuthorizationSigningKeyProtectionProperties properties) {
		Objects.requireNonNull(properties, "Authorization signing-key protection properties must not be null");
		this.activeKeyId = properties.activeKeyId();
		Map<String, byte[]> decodedKeys = properties.decodedKeys();
		Map<String, SecretKeySpec> configuredKeys = new LinkedHashMap<>();
		try {
			decodedKeys.forEach((keyId, key) -> configuredKeys.put(keyId, deriveKey(key)));
		}
		finally {
			decodedKeys.values().forEach(key -> Arrays.fill(key, (byte) 0));
		}
		this.keys = Map.copyOf(configuredKeys);
	}

	MetadataAttestation attest(StoredAuthorizationSigningKey stored) {
		requireConfigured();
		return new MetadataAttestation(VERSION, this.activeKeyId,
				mac(this.keys.get(this.activeKeyId), stored, VERSION, this.activeKeyId));
	}

	void verify(StoredAuthorizationSigningKey stored) {
		Objects.requireNonNull(stored, "Stored signing key must not be null");
		MetadataAttestation attestation = stored.attestation();
		if (attestation == null || attestation.version() != VERSION) {
			throw new DataRetrievalFailureException("Unsupported authorization signing-key attestation version");
		}
		SecretKeySpec key = this.keys.get(attestation.keyId());
		if (key == null) {
			throw new DataRetrievalFailureException(
					"Authorization signing-key attestation key is unavailable: " + attestation.keyId());
		}
		byte[] expected = mac(key, stored, attestation.version(), attestation.keyId());
		try {
			if (!MessageDigest.isEqual(expected, attestation.tag())) {
				throw new DataRetrievalFailureException("Authorization signing-key attestation validation failed");
			}
		}
		finally {
			Arrays.fill(expected, (byte) 0);
		}
	}

	private void requireConfigured() {
		if (this.activeKeyId == null) {
			throw new IllegalStateException("Authorization signing-key protection is not configured");
		}
	}

	private static SecretKeySpec deriveKey(byte[] key) {
		byte[] derived = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(key, "HmacSHA256"));
			derived = mac.doFinal(DERIVATION_LABEL);
			return new SecretKeySpec(derived, "HmacSHA256");
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Authorization signing-key attestation key derivation failed", exception);
		}
		finally {
			if (derived != null) {
				Arrays.fill(derived, (byte) 0);
			}
		}
	}

	private static byte[] mac(SecretKeySpec key, StoredAuthorizationSigningKey stored, int version, String keyId) {
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			return mac.doFinal(metadata(stored, version, keyId));
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Authorization signing-key attestation failed", exception);
		}
	}

	private static byte[] metadata(StoredAuthorizationSigningKey stored, int version, String keyId) {
		try {
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			try (DataOutputStream output = new DataOutputStream(bytes)) {
				output.writeUTF("iam.authorization.signing-key.metadata");
				output.writeShort(version);
				output.writeUTF(keyId);
				output.writeLong(stored.signingKeyId().getMostSignificantBits());
				output.writeLong(stored.signingKeyId().getLeastSignificantBits());
				output.writeUTF(stored.kid());
				output.writeUTF("RSA");
				output.writeUTF("sig");
				output.writeUTF("RS256");
				writeBytes(output, stored.publicModulus());
				output.writeInt(stored.publicExponent());
				output.writeUTF(stored.status().databaseValue());
				AuthorizationSigningKeyCipher.ProtectedPrivateKey privateKey = stored.privateKey();
				output.writeBoolean(privateKey != null);
				if (privateKey != null) {
					output.writeUTF("PKCS8");
					output.writeShort(1);
					output.writeUTF(privateKey.keyId());
					writeBytes(output, privateKey.initializationVector());
					writeBytes(output, privateKey.ciphertext());
				}
				writeInstant(output, stored.createdAt());
				writeInstant(output, stored.publishedAt());
				writeInstant(output, stored.activateAfter());
				writeNullableInstant(output, stored.activatedAt());
				writeNullableInstant(output, stored.retiredAt());
				writeNullableInstant(output, stored.publishUntil());
				writeNullableInstant(output, stored.privateKeyDestroyedAt());
				output.writeLong(stored.version());
				writeInstant(output, stored.updatedAt());
			}
			return bytes.toByteArray();
		}
		catch (IOException exception) {
			throw new IllegalStateException("Authorization signing-key metadata encoding failed", exception);
		}
	}

	private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
		output.writeInt(value.length);
		output.write(value);
	}

	private static void writeNullableInstant(DataOutputStream output, Instant value) throws IOException {
		output.writeBoolean(value != null);
		if (value != null) {
			writeInstant(output, value);
		}
	}

	private static void writeInstant(DataOutputStream output, Instant value) throws IOException {
		output.writeLong(value.getEpochSecond());
		output.writeInt(value.getNano());
	}

	record MetadataAttestation(int version, String keyId, byte[] tag) {

		MetadataAttestation {
			Objects.requireNonNull(keyId, "Attestation key ID must not be null");
			tag = Objects.requireNonNull(tag, "Attestation tag must not be null").clone();
		}

		@Override
		public byte[] tag() {
			return this.tag.clone();
		}

	}

}
