package com.ixayda.iam.credential;

import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.Destroyable;

public final class TotpCodeAttempt implements Destroyable, AutoCloseable {

	private final char[] value;

	private boolean destroyed;

	public TotpCodeAttempt(char[] value) {
		Objects.requireNonNull(value, "TOTP code attempt must not be null");
		if (value.length != TotpCredential.STANDARD_DIGITS || !containsOnlyAsciiDigits(value)) {
			throw new IllegalArgumentException("TOTP code attempt must contain exactly six ASCII digits");
		}
		this.value = value.clone();
	}

	/**
	 * Returns a caller-owned copy that should be cleared immediately after use.
	 */
	public synchronized char[] copy() {
		requireNotDestroyed();
		return this.value.clone();
	}

	@Override
	public synchronized void destroy() {
		if (!this.destroyed) {
			Arrays.fill(this.value, '\0');
			this.destroyed = true;
		}
	}

	@Override
	public synchronized boolean isDestroyed() {
		return this.destroyed;
	}

	@Override
	public void close() {
		destroy();
	}

	@Override
	public String toString() {
		return "TotpCodeAttempt[redacted]";
	}

	private static boolean containsOnlyAsciiDigits(char[] value) {
		for (char character : value) {
			if (character < '0' || character > '9') {
				return false;
			}
		}
		return true;
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("TOTP code attempt has been destroyed");
		}
	}

}
