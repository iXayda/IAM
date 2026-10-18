package com.ixayda.iam.credential;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Versioned authenticated encryption, bound to both the owner and the factor incarnation. */
@Component
public final class TotpSecrets {

	private final SecureRandom random = new SecureRandom();
	private final SecretKeySpec key;
	private final String keyId;

	TotpSecrets(@Value("${iam.totp.key-file:}") String keyFile) {
		if (keyFile.isEmpty()) {
			this.key = null;
			this.keyId = null;
			return;
		}
		byte[] bytes = null;
		try (var input = Files.newInputStream(Path.of(keyFile))) {
			bytes = input.readNBytes(33);
			if (bytes.length != 32) {
				throw new IllegalStateException("TOTP key file must contain exactly 32 raw bytes");
			}
			this.key = new SecretKeySpec(bytes, "AES");
			this.keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
		}
		catch (IOException | GeneralSecurityException ex) {
			throw new IllegalStateException("TOTP protection key is unavailable", ex);
		}
		finally {
			if (bytes != null) { Arrays.fill(bytes, (byte) 0); }
		}
	}

	public void requireConfigured() {
		if (this.key == null) {
			throw new IllegalStateException("TOTP requires an external protection key");
		}
	}

	public String keyId() {
		requireConfigured();
		return this.keyId;
	}

	public byte[] generate() {
		requireConfigured();
		byte[] secret = new byte[20];
		this.random.nextBytes(secret);
		return secret;
	}

	public String encrypt(UUID userId, UUID factorId, byte[] secret) {
		requireConfigured();
		if (secret == null || secret.length != 20) {
			throw new IllegalArgumentException("TOTP secret requires 20 bytes");
		}
		byte[] nonce = new byte[12];
		this.random.nextBytes(nonce);
		try {
			Cipher cipher = cipher(Cipher.ENCRYPT_MODE, userId, factorId, nonce);
			byte[] encrypted = cipher.doFinal(secret);
			byte[] envelope = Arrays.copyOf(nonce, nonce.length + encrypted.length);
			System.arraycopy(encrypted, 0, envelope, nonce.length, encrypted.length);
			return "v1." + Base64.getUrlEncoder().withoutPadding().encodeToString(envelope);
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("TOTP secret encryption failed", ex);
		}
	}

	public byte[] decrypt(UUID userId, UUID factorId, String storedKeyId, String encrypted) {
		requireConfigured();
		if (!this.keyId.equals(storedKeyId) || encrypted == null || !encrypted.matches("v1\\.[A-Za-z0-9_-]{64}")) {
			throw new IllegalStateException("TOTP secret cannot be decrypted with the configured key");
		}
		try {
			byte[] envelope = Base64.getUrlDecoder().decode(encrypted.substring(3));
			return cipher(Cipher.DECRYPT_MODE, userId, factorId, Arrays.copyOf(envelope, 12))
					.doFinal(envelope, 12, envelope.length - 12);
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("TOTP secret authentication failed", ex);
		}
	}

	private Cipher cipher(int mode, UUID userId, UUID factorId, byte[] nonce) throws GeneralSecurityException {
		Objects.requireNonNull(userId, "TOTP owner is required");
		Objects.requireNonNull(factorId, "TOTP factor id is required");
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(mode, this.key, new GCMParameterSpec(128, nonce));
		cipher.updateAAD(("iam:totp:v1:" + userId + ":" + factorId).getBytes(StandardCharsets.US_ASCII));
		return cipher;
	}

}
