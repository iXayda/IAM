package com.ixayda.iam.account.internal;

import java.util.Objects;

final class Base32Encoding {

	private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

	private Base32Encoding() {
	}

	static String encode(byte[] value) {
		Objects.requireNonNull(value, "Base32 input must not be null");
		if (value.length == 0) {
			return "";
		}
		StringBuilder encoded = new StringBuilder((value.length * 8 + 4) / 5);
		int buffer = value[0] & 0xff;
		int next = 1;
		int bitsLeft = 8;
		while (bitsLeft > 0 || next < value.length) {
			if (bitsLeft < 5) {
				if (next < value.length) {
					buffer = buffer << 8 | value[next++] & 0xff;
					bitsLeft += 8;
				}
				else {
					buffer <<= 5 - bitsLeft;
					bitsLeft = 5;
				}
			}
			encoded.append(ALPHABET[buffer >> bitsLeft - 5 & 0x1f]);
			bitsLeft -= 5;
		}
		return encoded.toString();
	}

}
