package com.ixayda.iam.credential.internal;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.credential.totp-secret-protection")
record TotpSecretProtectionProperties(String activeKeyId, Map<String, String> keys) {

	private static final int KEY_BYTES = 32;

	TotpSecretProtectionProperties {
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
		validateDistinctKeyMaterial(configuredKeys);
		keys = Map.copyOf(configuredKeys);
		if (activeKeyId == null && !keys.isEmpty()) {
			throw new IllegalArgumentException("An active TOTP secret protection key ID is required");
		}
		if (activeKeyId != null && !keys.containsKey(activeKeyId)) {
			throw new IllegalArgumentException("The active TOTP secret protection key is not configured");
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
		return "TotpSecretProtectionProperties[activeKeyId=" + this.activeKeyId
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
					"TOTP secret protection key IDs must contain 1 to 64 letters, digits, dots, underscores, or hyphens");
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
					"TOTP secret protection key '" + keyId + "' must be valid Base64", exception);
		}
		try {
			if (decoded.length != KEY_BYTES) {
				throw new IllegalArgumentException(
						"TOTP secret protection key '" + keyId + "' must contain exactly 32 bytes");
			}
		}
		finally {
			Arrays.fill(decoded, (byte) 0);
		}
	}

	private static void validateDistinctKeyMaterial(Map<String, String> configuredKeys) {
		List<byte[]> decodedKeys = configuredKeys.values()
			.stream()
			.map(Base64.getDecoder()::decode)
			.toList();
		try {
			for (int left = 0; left < decodedKeys.size(); left++) {
				for (int right = left + 1; right < decodedKeys.size(); right++) {
					if (MessageDigest.isEqual(decodedKeys.get(left), decodedKeys.get(right))) {
						throw new IllegalArgumentException(
								"TOTP secret protection keys must use distinct key material");
					}
				}
			}
		}
		finally {
			decodedKeys.forEach(key -> Arrays.fill(key, (byte) 0));
		}
	}

}
