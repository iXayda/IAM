package com.ixayda.iam.credential;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/** External protection key and authenticated, record-bound encryption of RSA signing material. */
@Component
@Lazy
public final class SigningKeySecrets {

	private static final int RSA_BITS = 3072;
	private static final int NONCE_BYTES = 12;
	private static final byte ENVELOPE_VERSION = 1;

	private final SecureRandom random = new SecureRandom();
	private final SecretKeySpec key;
	private final String protectionKeyId;

	public SigningKeySecrets(@Value("${iam.signing.key-file:}") String keyFile) {
		if (keyFile.isEmpty()) {
			this.key = null;
			this.protectionKeyId = null;
			return;
		}
		byte[] bytes = null;
		try (var input = Files.newInputStream(Path.of(keyFile))) {
			bytes = input.readNBytes(33);
			if (bytes.length != 32) {
				throw new IllegalStateException("Signing protection key file must contain exactly 32 raw bytes");
			}
			this.key = new SecretKeySpec(bytes, "AES");
			this.protectionKeyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
		}
		catch (IOException | GeneralSecurityException ex) {
			throw new IllegalStateException("Signing protection key is unavailable", ex);
		}
		finally {
			if (bytes != null) { Arrays.fill(bytes, (byte) 0); }
		}
	}

	public boolean isConfigured() { return this.key != null; }

	public void requireConfigured() {
		if (!isConfigured()) { throw new IllegalStateException("Signing requires an external protection key"); }
	}

	public String protectionKeyId() {
		requireConfigured();
		return this.protectionKeyId;
	}

	public KeyPair generate() {
		requireConfigured();
		try {
			var generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(new RSAKeyGenParameterSpec(RSA_BITS, RSAKeyGenParameterSpec.F4), this.random);
			return generator.generateKeyPair();
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Signing key generation failed", ex);
		}
	}

	public byte[] encrypt(UUID id, PrivateKey privateKey) {
		requireConfigured();
		Objects.requireNonNull(privateKey, "Signing private key is required");
		if (!(privateKey instanceof RSAPrivateKey rsa) || rsa.getModulus().bitLength() != RSA_BITS) {
			throw new IllegalArgumentException("Signing private key must be RSA 3072");
		}
		byte[] plaintext = privateKey.getEncoded();
		try {
			if (plaintext == null || plaintext.length < 1024 || plaintext.length > 4000) {
				throw new IllegalArgumentException("Signing private key encoding is invalid");
			}
			byte[] nonce = new byte[NONCE_BYTES];
			this.random.nextBytes(nonce);
			byte[] ciphertext = cipher(Cipher.ENCRYPT_MODE, id, nonce).doFinal(plaintext);
			byte[] envelope = new byte[1 + NONCE_BYTES + ciphertext.length];
			envelope[0] = ENVELOPE_VERSION;
			System.arraycopy(nonce, 0, envelope, 1, NONCE_BYTES);
			System.arraycopy(ciphertext, 0, envelope, 1 + NONCE_BYTES, ciphertext.length);
			return envelope;
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Signing private key encryption failed", ex);
		}
		finally {
			if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); }
		}
	}

	public KeyPair restore(UUID id, String algorithm, byte[] publicKey, String protectionKeyId, byte[] encrypted) {
		requireConfigured();
		if (!"RS256".equals(algorithm) || !this.protectionKeyId.equals(protectionKeyId) || encrypted == null
				|| encrypted.length < 1024 || encrypted.length > 4096 || encrypted[0] != ENVELOPE_VERSION) {
			throw new IllegalStateException("Persisted signing material is invalid for the configured protection key");
		}
		byte[] plaintext = null;
		try {
			plaintext = cipher(Cipher.DECRYPT_MODE, id, Arrays.copyOfRange(encrypted, 1, 1 + NONCE_BYTES))
					.doFinal(encrypted, 1 + NONCE_BYTES, encrypted.length - 1 - NONCE_BYTES);
			var privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(plaintext));
			var restoredPublicKey = readPublicKey(publicKey);
			// Matching modulus alone does not establish that the private exponent is usable.
			byte[] challenge = new byte[32];
			this.random.nextBytes(challenge);
			var signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey, this.random);
			signature.update(challenge);
			byte[] proof = signature.sign();
			signature.initVerify(restoredPublicKey);
			signature.update(challenge);
			if (!signature.verify(proof)) { throw new IllegalStateException("Persisted signing key pair does not match"); }
			return new KeyPair(restoredPublicKey, privateKey);
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Persisted signing material could not be authenticated", ex);
		}
		finally {
			if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); }
		}
	}

	/** Public material can be validated without loading or decrypting a private key. */
	public RSAPublicKey readPublicKey(byte[] encoded) {
		if (encoded == null || encoded.length > 1024) {
			throw new IllegalStateException("Persisted signing public key is invalid");
		}
		try {
			var restored = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
			if (restored.getModulus().bitLength() != RSA_BITS || !RSAKeyGenParameterSpec.F4.equals(restored.getPublicExponent())) {
				throw new IllegalStateException("Persisted signing public key must be RSA 3072 with exponent 65537");
			}
			return restored;
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Persisted signing public key is invalid", ex);
		}
	}

	private Cipher cipher(int mode, UUID id, byte[] nonce) throws GeneralSecurityException {
		Objects.requireNonNull(id, "Signing key id is required");
		var cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(mode, this.key, new GCMParameterSpec(128, nonce));
		cipher.updateAAD(("iam:signing-key:v1:RS256:" + id + ":" + this.protectionKeyId).getBytes(StandardCharsets.US_ASCII));
		return cipher;
	}

}
