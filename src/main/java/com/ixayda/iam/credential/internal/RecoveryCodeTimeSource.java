package com.ixayda.iam.credential.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

final class RecoveryCodeTimeSource {

	private final Clock clock;

	RecoveryCodeTimeSource() {
		this(Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000)));
	}

	RecoveryCodeTimeSource(Clock clock) {
		this.clock = Objects.requireNonNull(clock, "Recovery code clock must not be null");
	}

	Instant now() {
		return this.clock.instant();
	}

}
