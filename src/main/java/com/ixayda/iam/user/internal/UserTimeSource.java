package com.ixayda.iam.user.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.stereotype.Component;

@Component
class UserTimeSource {

	private final Clock clock = Clock.tick(Clock.systemUTC(), Duration.ofNanos(1_000));

	Instant now() {
		return this.clock.instant();
	}

}
