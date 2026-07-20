package com.ixayda.iam.auth.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

final class AuthenticationTimeSource {

	private final Clock clock;

	AuthenticationTimeSource() {
		this(Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000)));
	}

	AuthenticationTimeSource(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "Authentication clock must not be null");
	}

	Instant now() {
		return this.clock.instant();
	}

}
