package com.ixayda.iam.credential;

import java.time.Instant;
import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public record TotpCredential(TotpCredentialId id, TenantId tenantId, UserId userId, TotpCredentialStatus status,
		TotpAlgorithm algorithm, int digits, int periodSeconds, Long lastAcceptedTimeStep, long version,
		Instant createdAt, Instant updatedAt, Instant enrollmentExpiresAt, Instant activatedAt, Instant revokedAt) {

	public static final TotpAlgorithm STANDARD_ALGORITHM = TotpAlgorithm.SHA1;

	public static final int STANDARD_DIGITS = 6;

	public static final int STANDARD_PERIOD_SECONDS = 30;

	public static final int STANDARD_SECRET_BYTES = 20;

	public TotpCredential {
		Objects.requireNonNull(id, "TOTP credential ID must not be null");
		Objects.requireNonNull(tenantId, "TOTP credential tenant ID must not be null");
		Objects.requireNonNull(userId, "TOTP credential user ID must not be null");
		Objects.requireNonNull(status, "TOTP credential status must not be null");
		Objects.requireNonNull(algorithm, "TOTP algorithm must not be null");
		Objects.requireNonNull(createdAt, "TOTP credential creation time must not be null");
		Objects.requireNonNull(updatedAt, "TOTP credential update time must not be null");
		if (algorithm != STANDARD_ALGORITHM || digits != STANDARD_DIGITS
				|| periodSeconds != STANDARD_PERIOD_SECONDS) {
			throw new IllegalArgumentException("TOTP credential parameters are unsupported");
		}
		if (version < 0 || lastAcceptedTimeStep != null && lastAcceptedTimeStep < 0) {
			throw new IllegalArgumentException("TOTP credential counters must not be negative");
		}
		if (updatedAt.isBefore(createdAt)) {
			throw new IllegalArgumentException("TOTP credential update time must not precede creation time");
		}
		validateLifecycle(status, lastAcceptedTimeStep, version, createdAt, updatedAt, enrollmentExpiresAt, activatedAt,
				revokedAt);
	}

	public static TotpCredential pending(TenantId tenantId, UserId userId, Instant createdAt,
			Instant enrollmentExpiresAt) {
		return new TotpCredential(TotpCredentialId.random(), tenantId, userId, TotpCredentialStatus.PENDING,
				STANDARD_ALGORITHM, STANDARD_DIGITS, STANDARD_PERIOD_SECONDS, null, 0, createdAt, createdAt,
				enrollmentExpiresAt, null, null);
	}

	public boolean isPendingAt(Instant instant) {
		Objects.requireNonNull(instant, "TOTP credential evaluation time must not be null");
		return this.status == TotpCredentialStatus.PENDING && instant.isBefore(this.enrollmentExpiresAt);
	}

	public boolean isActive() {
		return this.status == TotpCredentialStatus.ACTIVE;
	}

	public TotpCredential activate(long acceptedTimeStep, Instant confirmedAt) {
		Objects.requireNonNull(confirmedAt, "TOTP credential confirmation time must not be null");
		if (!isPendingAt(confirmedAt) || confirmedAt.isBefore(this.updatedAt) || acceptedTimeStep < 0) {
			throw new IllegalStateException("TOTP credential cannot be activated");
		}
		return new TotpCredential(this.id, this.tenantId, this.userId, TotpCredentialStatus.ACTIVE,
				this.algorithm, this.digits, this.periodSeconds, acceptedTimeStep, nextVersion(), this.createdAt,
				confirmedAt, null, confirmedAt, null);
	}

	public TotpCredential accept(long timeStep, Instant verifiedAt) {
		Objects.requireNonNull(verifiedAt, "TOTP verification time must not be null");
		if (!isActive() || timeStep < 0 || timeStep <= this.lastAcceptedTimeStep
				|| verifiedAt.isBefore(this.updatedAt)) {
			throw new IllegalStateException("TOTP time step cannot be accepted");
		}
		return new TotpCredential(this.id, this.tenantId, this.userId, this.status, this.algorithm, this.digits,
				this.periodSeconds, timeStep, nextVersion(), this.createdAt, verifiedAt, null, this.activatedAt, null);
	}

	public TotpCredential revoke(Instant revokedAt) {
		Objects.requireNonNull(revokedAt, "TOTP revocation time must not be null");
		if (this.status == TotpCredentialStatus.REVOKED) {
			return this;
		}
		Instant effectiveRevocationTime = revokedAt.isBefore(this.updatedAt) ? this.updatedAt : revokedAt;
		return new TotpCredential(this.id, this.tenantId, this.userId, TotpCredentialStatus.REVOKED,
				this.algorithm, this.digits, this.periodSeconds, this.lastAcceptedTimeStep, nextVersion(),
				this.createdAt, effectiveRevocationTime, null, this.activatedAt, effectiveRevocationTime);
	}

	private long nextVersion() {
		return Math.incrementExact(this.version);
	}

	private static void validateLifecycle(TotpCredentialStatus status, Long lastAcceptedTimeStep, long version,
			Instant createdAt, Instant updatedAt, Instant enrollmentExpiresAt, Instant activatedAt, Instant revokedAt) {
		if (activatedAt != null && (activatedAt.isBefore(createdAt) || activatedAt.isAfter(updatedAt))) {
			throw new IllegalArgumentException("TOTP activation time is invalid");
		}
		if (revokedAt != null && (revokedAt.isBefore(createdAt) || !revokedAt.equals(updatedAt))) {
			throw new IllegalArgumentException("TOTP revocation time is invalid");
		}
		switch (status) {
			case PENDING -> {
				if (enrollmentExpiresAt == null || !enrollmentExpiresAt.isAfter(createdAt) || activatedAt != null
						|| revokedAt != null || lastAcceptedTimeStep != null) {
					throw new IllegalArgumentException("Pending TOTP credential lifecycle is invalid");
				}
			}
			case ACTIVE -> {
				if (version == 0 || enrollmentExpiresAt != null || activatedAt == null || revokedAt != null
						|| lastAcceptedTimeStep == null) {
					throw new IllegalArgumentException("Active TOTP credential lifecycle is invalid");
				}
			}
			case REVOKED -> {
				if (version == 0 || enrollmentExpiresAt != null || revokedAt == null
						|| (activatedAt == null) != (lastAcceptedTimeStep == null)) {
					throw new IllegalArgumentException("Revoked TOTP credential lifecycle is invalid");
				}
			}
		}
	}

}
