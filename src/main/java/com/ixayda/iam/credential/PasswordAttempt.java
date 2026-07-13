package com.ixayda.iam.credential;

import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.Destroyable;

public final class PasswordAttempt implements Destroyable, AutoCloseable {

	public static final int MAX_LENGTH = 256;

	private final char[] value;

	private boolean destroyed;

	public PasswordAttempt(char[] value) {
		Objects.requireNonNull(value, "Password attempt must not be null");
		if (value.length == 0 || value.length > MAX_LENGTH) {
			throw new IllegalArgumentException("Password attempt must contain 1 to 256 characters");
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

	public synchronized int length() {
		requireNotDestroyed();
		return this.value.length;
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
		return "PasswordAttempt[redacted]";
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("Password attempt has been destroyed");
		}
	}

}
