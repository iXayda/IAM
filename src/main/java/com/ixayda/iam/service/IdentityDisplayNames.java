package com.ixayda.iam.service;

import java.text.Normalizer;

/** Shared display-name and matching search-text rules. */
final class IdentityDisplayNames {

	private IdentityDisplayNames() { }

	static String normalize(String value, String error) {
		if (value == null || value.length() > 65_536) {
			throw new IllegalArgumentException(error);
		}
		for (int i = 0; i < value.length(); i++) {
			char current = value.charAt(i);
			if (Character.isHighSurrogate(current)) {
				if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) {
					throw new IllegalArgumentException(error);
				}
			}
			else if (Character.isLowSurrogate(current)) {
				throw new IllegalArgumentException(error);
			}
		}
		String normalized = Normalizer.normalize(value, Normalizer.Form.NFC);
		int length = normalized.codePointCount(0, normalized.length());
		if (length < 1 || length > 128 || normalized.codePoints().anyMatch(Character::isISOControl)
				|| normalized.codePoints().allMatch(cp -> Character.isWhitespace(cp) || Character.isSpaceChar(cp))) {
			throw new IllegalArgumentException(error);
		}
		return normalized;
	}

}
