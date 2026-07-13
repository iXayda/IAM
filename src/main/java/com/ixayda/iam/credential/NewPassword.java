package com.ixayda.iam.credential;

import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.Destroyable;

public final class NewPassword implements Destroyable, AutoCloseable {

	public static final int MIN_LENGTH = 8;

	public static final int MAX_LENGTH = 256;

	private final char[] value;

	private boolean destroyed;

	public NewPassword(char[] value) {
		Objects.requireNonNull(value, "New password must not be null");
		if (value.length < MIN_LENGTH || value.length > MAX_LENGTH || isBlank(value)) {
			throw new IllegalArgumentException("New password must contain 8 to 256 characters and not be blank");
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
		return "NewPassword[redacted]";
	}

	private static boolean isBlank(char[] value) {
		for (char character : value) {
			if (!Character.isWhitespace(character)) {
				return false;
			}
		}
		return true;
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("New password has been destroyed");
		}
	}

}
