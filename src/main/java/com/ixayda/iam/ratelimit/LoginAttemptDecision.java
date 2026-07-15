package com.ixayda.iam.ratelimit;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

public final class LoginAttemptDecision {

	private static final LoginAttemptDecision UNAVAILABLE = new LoginAttemptDecision(LoginAttemptStatus.UNAVAILABLE,
			null, null);

	private final LoginAttemptStatus status;

	private final Duration retryAfter;

	private final LoginAttemptLease lease;

	private LoginAttemptDecision(LoginAttemptStatus status, Duration retryAfter, LoginAttemptLease lease) {
		this.status = status;
		this.retryAfter = retryAfter;
		this.lease = lease;
	}

	public static LoginAttemptDecision allowed(LoginAttemptLease lease) {
		return new LoginAttemptDecision(LoginAttemptStatus.ALLOWED, null,
				Objects.requireNonNull(lease, "Allowed login attempt lease must not be null"));
	}

	public static LoginAttemptDecision throttled(Duration retryAfter) {
		Objects.requireNonNull(retryAfter, "Retry-after duration must not be null");
		if (retryAfter.isZero() || retryAfter.isNegative()) {
			throw new IllegalArgumentException("Retry-after duration must be positive");
		}
		return new LoginAttemptDecision(LoginAttemptStatus.THROTTLED, retryAfter, null);
	}

	public static LoginAttemptDecision unavailable() {
		return UNAVAILABLE;
	}

	public LoginAttemptStatus status() {
		return this.status;
	}

	public boolean isAllowed() {
		return this.status == LoginAttemptStatus.ALLOWED;
	}

	public Optional<Duration> retryAfter() {
		return Optional.ofNullable(this.retryAfter);
	}

	public Optional<LoginAttemptLease> lease() {
		return Optional.ofNullable(this.lease);
	}

	@Override
	public String toString() {
		return "LoginAttemptDecision[status=" + this.status + "]";
	}

}
