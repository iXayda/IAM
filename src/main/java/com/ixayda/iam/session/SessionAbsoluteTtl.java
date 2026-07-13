package com.ixayda.iam.session;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public record SessionAbsoluteTtl(Duration value) {

	public static final Duration MINIMUM = Duration.ofNanos(1_000);

	public SessionAbsoluteTtl {
		Objects.requireNonNull(value, "Session absolute TTL must not be null");
		if (value.compareTo(MINIMUM) < 0) {
			throw new IllegalArgumentException("Session absolute TTL must be at least one microsecond");
		}
	}

	public Instant expiresAt(Instant authenticatedAt) {
		Objects.requireNonNull(authenticatedAt, "Session authentication time must not be null");
		try {
			return authenticatedAt.plus(this.value);
		}
		catch (DateTimeException | ArithmeticException ex) {
			throw new IllegalArgumentException("Session absolute TTL exceeds the supported time range", ex);
		}
	}

}
