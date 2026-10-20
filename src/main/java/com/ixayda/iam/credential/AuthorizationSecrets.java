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
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Independent encryption and lookup keys protect protocol columns and their token indexes. */
@Component
public final class AuthorizationSecrets {

	private final SecureRandom random = new SecureRandom();
	private final SecretKeySpec encryption;
	private final SecretKeySpec lookup;
	private final String keyId;

	public AuthorizationSecrets(@Value("${iam.authorization.key-file:}") String keyFile) {
		if (keyFile.isEmpty()) { this.encryption = null; this.lookup = null; this.keyId = null; return; }
		byte[] bytes = null;
		try (var input = Files.newInputStream(Path.of(keyFile))) {
			bytes = input.readNBytes(65);
			if (bytes.length != 64) { throw new IllegalStateException("Authorization key file must contain exactly 64 raw bytes"); }
			this.encryption = new SecretKeySpec(bytes, 0, 32, "AES");
			this.lookup = new SecretKeySpec(bytes, 32, 32, "HmacSHA256");
			this.keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
		}
		catch (IOException | GeneralSecurityException ex) { throw new IllegalStateException("Authorization protection keys are unavailable", ex); }
		finally { if (bytes != null) { Arrays.fill(bytes, (byte) 0); } }
	}

	public void requireConfigured() {
		if (this.encryption == null) { throw new IllegalStateException("Protocol persistence requires external protection keys"); }
	}

	public String encrypt(UUID authorizationId, String column, String binding, String value) {
		requireConfigured();
		byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
		try {
			if (plaintext.length > 65_536) { throw new IllegalArgumentException("Protocol column exceeds its bound"); }
			if (!new String(plaintext, StandardCharsets.UTF_8).equals(value)) { throw new IllegalArgumentException("Protocol column requires valid Unicode"); }
			byte[] nonce = new byte[12]; this.random.nextBytes(nonce);
			byte[] ciphertext = cipher(Cipher.ENCRYPT_MODE, authorizationId, column, binding, nonce).doFinal(plaintext);
			byte[] envelope = new byte[nonce.length + ciphertext.length];
			System.arraycopy(nonce, 0, envelope, 0, nonce.length);
			System.arraycopy(ciphertext, 0, envelope, nonce.length, ciphertext.length);
			return "enc:v1:" + this.keyId + ":" + Base64.getUrlEncoder().withoutPadding().encodeToString(envelope);
		}
		catch (GeneralSecurityException ex) { throw new IllegalStateException("Protocol column could not be encrypted", ex); }
		finally { Arrays.fill(plaintext, (byte) 0); }
	}

	public String decrypt(UUID authorizationId, String column, String binding, String value) {
		requireConfigured();
		String prefix = "enc:v1:" + this.keyId + ":";
		if (value == null || value.length() > 131_072 || !value.startsWith(prefix)) { throw invalid(); }
		byte[] plaintext = null;
		try {
			String encoded = value.substring(prefix.length());
			byte[] envelope = Base64.getUrlDecoder().decode(encoded);
			if (envelope.length < 28 || !Base64.getUrlEncoder().withoutPadding().encodeToString(envelope).equals(encoded)) { throw invalid(); }
			plaintext = cipher(Cipher.DECRYPT_MODE, authorizationId, column, binding, Arrays.copyOfRange(envelope, 0, 12))
					.doFinal(envelope, 12, envelope.length - 12);
			if (plaintext.length > 65_536) { throw invalid(); }
			String decoded = new String(plaintext, StandardCharsets.UTF_8);
			if (!Arrays.equals(plaintext, decoded.getBytes(StandardCharsets.UTF_8))) { throw invalid(); }
			return decoded;
		}
		catch (GeneralSecurityException | IllegalArgumentException ex) { throw invalid(); }
		finally { if (plaintext != null) { Arrays.fill(plaintext, (byte) 0); } }
	}

	/** Lookup is domain separated from encryption and covers all supported token types. */
	public String digest(String value) {
		return lookup("iam:authorization-lookup:v1:", value, 16_384);
	}

	/** Refresh history is a separate purpose from the native current-token index. */
	public String refreshDigest(String value) { return lookup("iam:refresh-lookup:v1:", value, 16_384); }

	/** Authenticates history ownership, generation, parent and timestamps, including the spent transition. */
	public String refreshHistorySeal(String canonical) { return lookup("iam:refresh-history:v1:", canonical, 4096); }

	public boolean verifiesRefreshHistory(String canonical, String seal) {
		return seal != null && seal.matches("[0-9a-f]{64}") && MessageDigest.isEqual(HexFormat.of().parseHex(seal), HexFormat.of().parseHex(refreshHistorySeal(canonical)));
	}

	/** Opaque browser owners and one-time interaction handles are separate from OAuth credentials. */
	public String generateInteractionSecret() {
		requireConfigured();
		byte[] bytes = new byte[32]; this.random.nextBytes(bytes);
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	public String interactionDigest(String value) { return lookup("iam:interaction-handle:v1:", value, 43); }
	public String interactionOwnerDigest(String value) { return lookup("iam:interaction-owner:v1:", value, 43); }
	public String interactionBinding(String canonical) { return lookup("iam:interaction-binding:v1:", canonical, 1024); }

	/** Stable initialization prevents independent JDBC snapshots from assigning different owners to one session. */
	public String interactionSessionOwner(String sessionId) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(HexFormat.of().parseHex(lookup("iam:interaction-session-owner:v1:", sessionId, 128)));
	}

	private String lookup(String domain, String value, int maximum) {
		requireConfigured();
		if (value == null || value.isEmpty() || value.length() > maximum) { throw new IllegalArgumentException("Protocol token is invalid"); }
		byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
		try {
			if (!new String(encoded, StandardCharsets.UTF_8).equals(value)) { throw new IllegalArgumentException("Protocol token requires valid Unicode"); }
			var mac = Mac.getInstance("HmacSHA256"); mac.init(this.lookup);
			mac.update(domain.getBytes(StandardCharsets.US_ASCII));
			return HexFormat.of().formatHex(mac.doFinal(encoded));
		}
		catch (GeneralSecurityException ex) { throw new IllegalStateException("Protocol lookup is unavailable", ex); }
		finally { Arrays.fill(encoded, (byte) 0); }
	}

	private Cipher cipher(int mode, UUID id, String column, String binding, byte[] nonce) throws GeneralSecurityException {
		if (id == null || column == null || !column.matches("[a-z_]{1,64}") || binding == null || !binding.matches("[0-9a-f]{64}")) { throw new IllegalArgumentException("Protocol encryption context is invalid"); }
		var cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(mode, this.encryption, new GCMParameterSpec(128, nonce));
		cipher.updateAAD(("iam:authorization:v1:" + this.keyId + ":" + id + ":" + column + ":" + binding).getBytes(StandardCharsets.US_ASCII));
		return cipher;
	}

	private static IllegalStateException invalid() { return new IllegalStateException("Persisted protocol column could not be authenticated"); }

}
