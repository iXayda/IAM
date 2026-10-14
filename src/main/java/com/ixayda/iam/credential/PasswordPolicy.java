package com.ixayda.iam.credential;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import static com.ixayda.iam.credential.PasswordRejectedException.Reason.*;

/** Rules for setting a password; verification only applies the same normalization. */
@Component
public final class PasswordPolicy {

	public static final int MIN_LENGTH = 15;

	public static final int MAX_LENGTH = 256;

	private static final Set<String> COMMON_SUFFIXES = Set.of("1", "123", "123456", "123456789", "!", "123!");

	private final Set<String> blockedPasswords;

	private final String serviceName;

	public PasswordPolicy(@Value("${spring.application.name}") String serviceName) {
		this.serviceName = normalizeContextName(serviceName);
		this.blockedPasswords = readBlocklist(
				PasswordPolicy.class.getResourceAsStream("/credential/password-blocklist.txt"));
	}

	public String normalizeAndValidate(String password, String username) {
		String normalized = normalize(password);
		if (normalized.codePointCount(0, normalized.length()) < MIN_LENGTH) {
			throw new PasswordRejectedException(INVALID_LENGTH);
		}
		String accountName = normalizeContextName(username);
		String comparisonValue = normalizeForComparison(normalized);
		if (isBlank(normalized) || this.blockedPasswords.contains(comparisonValue)
				|| matchesNameOrDerivative(normalized, accountName)
				|| matchesNameOrDerivative(normalized, this.serviceName)) {
			throw new PasswordRejectedException(WEAK_PASSWORD);
		}
		return normalized;
	}

	private static String normalizeContextName(String value) {
		if (value == null || isBlank(value)) {
			throw new IllegalArgumentException("Password validation requires a valid account or service name");
		}
		try {
			return normalize(value);
		}
		catch (PasswordRejectedException ex) {
			throw new IllegalArgumentException("Password validation requires a valid account or service name");
		}
	}

	private static boolean isBlank(String value) {
		return value.codePoints().allMatch(codePoint -> Character.isWhitespace(codePoint)
				|| Character.isSpaceChar(codePoint) || codePoint == 0x85);
	}

	private static boolean matchesNameOrDerivative(String password, String name) {
		if (password.equalsIgnoreCase(name)
				|| password.equalsIgnoreCase(Normalizer.normalize(name.repeat(2), Normalizer.Form.NFC))) {
			return true;
		}
		for (String suffix : COMMON_SUFFIXES) {
			if (password.equalsIgnoreCase(name + suffix)) {
				return true;
			}
		}
		return false;
	}

	static String normalize(String password) {
		if (password == null || password.length() > 65_536) {
			throw new PasswordRejectedException(INVALID_LENGTH);
		}
		for (int i = 0; i < password.length(); i++) {
			char current = password.charAt(i);
			if (Character.isHighSurrogate(current)) {
				if (++i >= password.length() || !Character.isLowSurrogate(password.charAt(i))) {
					throw new PasswordRejectedException(INVALID_UNICODE);
				}
			}
			else if (Character.isLowSurrogate(current)) {
				throw new PasswordRejectedException(INVALID_UNICODE);
			}
		}
		String normalized = Normalizer.normalize(password, Normalizer.Form.NFC);
		int length = normalized.codePointCount(0, normalized.length());
		if (length < 1 || length > MAX_LENGTH) {
			throw new PasswordRejectedException(INVALID_LENGTH);
		}
		return normalized;
	}

	static Set<String> readBlocklist(InputStream input) {
		if (input == null) {
			throw new IllegalStateException("Password blocklist is unavailable");
		}
		try (var reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8.newDecoder()
				.onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)))) {
			Set<String> values = new HashSet<>();
			for (String line; (line = reader.readLine()) != null;) {
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}
				String normalized = normalize(line);
				if (normalized.codePointCount(0, normalized.length()) < MIN_LENGTH) {
					throw new IllegalStateException("Password blocklist contains an invalid entry");
				}
				values.add(normalizeForComparison(normalized));
			}
			if (values.isEmpty()) {
				throw new IllegalStateException("Password blocklist is empty");
			}
			return Set.copyOf(values);
		}
		catch (IOException | PasswordRejectedException ex) {
			throw new IllegalStateException("Password blocklist cannot be read");
		}
	}

	private static String normalizeForComparison(String value) {
		return Normalizer.normalize(value, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
	}

}
