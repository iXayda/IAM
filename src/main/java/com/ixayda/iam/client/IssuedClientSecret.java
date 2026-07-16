package com.ixayda.iam.client;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public final class IssuedClientSecret implements AutoCloseable {

	private static final int ENTROPY_BYTES = 32;

	private char[] value;

	private IssuedClientSecret(char[] value) {
		this.value = Arrays.copyOf(value, value.length);
	}

	public static IssuedClientSecret generate() {
		byte[] entropy = new byte[ENTROPY_BYTES];
		byte[] encoded = null;
		char[] value = null;
		try {
			new SecureRandom().nextBytes(entropy);
			encoded = Base64.getUrlEncoder().withoutPadding().encode(entropy);
			value = new char[encoded.length];
			for (int index = 0; index < encoded.length; index++) {
				value[index] = (char) encoded[index];
			}
			return new IssuedClientSecret(value);
		}
		finally {
			Arrays.fill(entropy, (byte) 0);
			if (encoded != null) {
				Arrays.fill(encoded, (byte) 0);
			}
			if (value != null) {
				Arrays.fill(value, '\0');
			}
		}
	}

	public synchronized char[] copy() {
		if (this.value == null) {
			throw new IllegalStateException("Client secret has been destroyed");
		}
		return Arrays.copyOf(this.value, this.value.length);
	}

	public synchronized boolean isDestroyed() {
		return this.value == null;
	}

	@Override
	public synchronized void close() {
		if (this.value != null) {
			Arrays.fill(this.value, '\0');
			this.value = null;
		}
	}

	@Override
	public String toString() {
		return "[PROTECTED]";
	}

}
