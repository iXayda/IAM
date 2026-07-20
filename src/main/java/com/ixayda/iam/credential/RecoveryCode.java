package com.ixayda.iam.credential;

import java.util.Arrays;

import javax.security.auth.Destroyable;

public final class RecoveryCode implements Destroyable, AutoCloseable {

	public static final int SYMBOL_COUNT = RecoveryCodeFormat.SYMBOL_COUNT;

	private final char[] value;

	private boolean destroyed;

	public RecoveryCode(char[] value) {
		this.value = RecoveryCodeFormat.requireCanonical(value);
	}

	/**
	 * Returns a caller-owned copy that should be cleared immediately after use.
	 */
	public synchronized char[] copy() {
		requireNotDestroyed();
		return this.value.clone();
	}

	public synchronized String selector() {
		requireNotDestroyed();
		return RecoveryCodeFormat.selector(this.value);
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
		return "RecoveryCode[redacted]";
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("Recovery code has been destroyed");
		}
	}

}
