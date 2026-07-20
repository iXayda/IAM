package com.ixayda.iam.auth.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

final class MfaChallengeTimeSource {

	private final Clock clock;

	MfaChallengeTimeSource() {
		this(Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000)));
	}

	MfaChallengeTimeSource(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "MFA challenge clock must not be null");
	}

	Instant now() {
		return this.clock.instant();
	}

}
