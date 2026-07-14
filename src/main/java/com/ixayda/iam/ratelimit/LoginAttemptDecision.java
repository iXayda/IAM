package com.ixayda.iam.ratelimit;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

public final class LoginAttemptDecision {

	private static final LoginAttemptDecision ALLOWED = new LoginAttemptDecision(LoginAttemptStatus.ALLOWED, null);

	private static final LoginAttemptDecision UNAVAILABLE =
			new LoginAttemptDecision(LoginAttemptStatus.UNAVAILABLE, null);

	private final LoginAttemptStatus status;

	private final Duration retryAfter;

	private LoginAttemptDecision(LoginAttemptStatus status, Duration retryAfter) {
		this.status = status;
		this.retryAfter = retryAfter;
	}

	public static LoginAttemptDecision allowed() {
		return ALLOWED;
	}

	public static LoginAttemptDecision throttled(Duration retryAfter) {
		Objects.requireNonNull(retryAfter, "Retry-after duration must not be null");
		if (retryAfter.isZero() || retryAfter.isNegative()) {
			throw new IllegalArgumentException("Retry-after duration must be positive");
		}
		return new LoginAttemptDecision(LoginAttemptStatus.THROTTLED, retryAfter);
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

	@Override
	public String toString() {
		return "LoginAttemptDecision[status=" + this.status + "]";
	}

}
