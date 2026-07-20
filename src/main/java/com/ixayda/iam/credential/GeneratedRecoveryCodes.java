package com.ixayda.iam.credential;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.Destroyable;

public final class GeneratedRecoveryCodes implements Destroyable, AutoCloseable {

	public static final int CODE_COUNT = 10;

	private final char[][] values;

	private boolean destroyed;

	public GeneratedRecoveryCodes(List<RecoveryCode> codes) {
		Objects.requireNonNull(codes, "Recovery codes must not be null");
		if (codes.size() != CODE_COUNT) {
			throw new IllegalArgumentException("A recovery code set must contain exactly ten codes");
		}
		this.values = new char[CODE_COUNT][];
		Set<String> selectors = new HashSet<>();
		try {
			for (int index = 0; index < codes.size(); index++) {
				RecoveryCode code = Objects.requireNonNull(codes.get(index), "Recovery code must not be null");
				if (!selectors.add(code.selector())) {
					throw new IllegalArgumentException("Recovery code selectors must be unique");
				}
				this.values[index] = code.copy();
			}
		}
		catch (RuntimeException ex) {
			clear(this.values);
			throw ex;
		}
	}

	/**
	 * Returns caller-owned copies. Every returned row should be cleared immediately
	 * after presentation to the user.
	 */
	public synchronized char[][] copy() {
		requireNotDestroyed();
		char[][] copy = new char[this.values.length][];
		for (int index = 0; index < this.values.length; index++) {
			copy[index] = this.values[index].clone();
		}
		return copy;
	}

	public synchronized int size() {
		requireNotDestroyed();
		return this.values.length;
	}

	@Override
	public synchronized void destroy() {
		if (!this.destroyed) {
			clear(this.values);
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
		return "GeneratedRecoveryCodes[count=" + CODE_COUNT + ", values=redacted]";
	}

	private static void clear(char[][] values) {
		for (char[] value : values) {
			if (value != null) {
				Arrays.fill(value, '\0');
			}
		}
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("Recovery code set has been destroyed");
		}
	}

}
