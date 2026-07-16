package com.ixayda.iam.authorization.internal;

import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.authorization.signing-key-protection")
record AuthorizationSigningKeyProtectionProperties(String activeKeyId, Map<String, String> keys) {

	private static final int KEY_BYTES = 32;

	AuthorizationSigningKeyProtectionProperties {
		activeKeyId = normalizeKeyId(activeKeyId);
		Map<String, String> configuredKeys = new LinkedHashMap<>();
		if (keys != null) {
			keys.forEach((keyId, encodedKey) -> {
				String normalizedKeyId = requireKeyId(keyId);
				if (encodedKey != null && !encodedKey.isBlank()) {
					validateEncodedKey(normalizedKeyId, encodedKey);
					configuredKeys.put(normalizedKeyId, encodedKey);
				}
			});
		}
		keys = Map.copyOf(configuredKeys);
		if (activeKeyId == null && !keys.isEmpty()) {
			throw new IllegalArgumentException("An active authorization signing-key protection key ID is required");
		}
		if (activeKeyId != null && !keys.containsKey(activeKeyId)) {
			throw new IllegalArgumentException("The active authorization signing-key protection key is not configured");
		}
	}

	boolean isConfigured() {
		return this.activeKeyId != null;
	}

	Map<String, byte[]> decodedKeys() {
		Map<String, byte[]> decoded = new LinkedHashMap<>();
		this.keys.forEach((keyId, encodedKey) -> decoded.put(keyId, Base64.getDecoder().decode(encodedKey)));
		return decoded;
	}

	@Override
	public String toString() {
		return "AuthorizationSigningKeyProtectionProperties[activeKeyId=" + this.activeKeyId
				+ ", configuredKeyCount=" + this.keys.size() + ", keys=redacted]";
	}

	private static String normalizeKeyId(String value) {
		return value == null || value.isBlank() ? null : requireKeyId(value);
	}

	private static String requireKeyId(String value) {
		if (value == null || value.isEmpty() || value.length() > 64
				|| !value.chars().allMatch(character -> character >= 'a' && character <= 'z'
						|| character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
						|| character == '.' || character == '_' || character == '-')) {
			throw new IllegalArgumentException(
					"Authorization signing-key protection key IDs must contain 1 to 64 letters, digits, dots, underscores, or hyphens");
		}
		return value;
	}

	private static void validateEncodedKey(String keyId, String encodedKey) {
		byte[] decoded;
		try {
			decoded = Base64.getDecoder().decode(encodedKey);
		}
		catch (IllegalArgumentException exception) {
			throw new IllegalArgumentException(
					"Authorization signing-key protection key '" + keyId + "' must be valid Base64", exception);
		}
		try {
			if (decoded.length != KEY_BYTES) {
				throw new IllegalArgumentException(
						"Authorization signing-key protection key '" + keyId + "' must contain exactly 32 bytes");
			}
		}
		finally {
			Arrays.fill(decoded, (byte) 0);
		}
	}

}
