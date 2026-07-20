package com.ixayda.iam.credential;

import java.util.Arrays;

import javax.security.auth.Destroyable;

public final class RecoveryCodeAttempt implements Destroyable, AutoCloseable {

	private final char[] value;

	private boolean destroyed;

	public RecoveryCodeAttempt(char[] value) {
		this.value = RecoveryCodeFormat.normalizeAttempt(value);
	}

	/**
	 * Returns a caller-owned canonical copy that should be cleared immediately after use.
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
		return "RecoveryCodeAttempt[redacted]";
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("Recovery code attempt has been destroyed");
		}
	}

}
