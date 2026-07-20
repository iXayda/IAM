package com.ixayda.iam.credential;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.Destroyable;

public final class TotpEnrollment implements Destroyable, AutoCloseable {

	private final TotpCredentialId credentialId;

	private final Instant expiresAt;

	private final byte[] secret;

	private boolean destroyed;

	public TotpEnrollment(TotpCredentialId credentialId, Instant expiresAt, byte[] secret) {
		this.credentialId = Objects.requireNonNull(credentialId, "TOTP enrollment credential ID must not be null");
		this.expiresAt = Objects.requireNonNull(expiresAt, "TOTP enrollment expiry must not be null");
		Objects.requireNonNull(secret, "TOTP enrollment secret must not be null");
		if (secret.length != TotpCredential.STANDARD_SECRET_BYTES) {
			throw new IllegalArgumentException("TOTP enrollment secret must contain exactly 20 bytes");
		}
		this.secret = secret.clone();
	}

	public TotpCredentialId credentialId() {
		return this.credentialId;
	}

	public Instant expiresAt() {
		return this.expiresAt;
	}

	/**
	 * Returns a caller-owned copy that should be cleared immediately after use.
	 */
	public synchronized byte[] copySecret() {
		requireNotDestroyed();
		return this.secret.clone();
	}

	@Override
	public synchronized void destroy() {
		if (!this.destroyed) {
			Arrays.fill(this.secret, (byte) 0);
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
		return "TotpEnrollment[credentialId=" + this.credentialId + ", expiresAt=" + this.expiresAt
				+ ", secret=redacted]";
	}

	private void requireNotDestroyed() {
		if (this.destroyed) {
			throw new IllegalStateException("TOTP enrollment secret has been destroyed");
		}
	}

}
