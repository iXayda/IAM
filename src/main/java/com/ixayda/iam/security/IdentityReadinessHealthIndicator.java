package com.ixayda.iam.security;

import java.util.function.Supplier;

import com.ixayda.iam.service.IdentityReadiness;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/** Public probe adapter deliberately carries no exception, key metadata or dependency details. */
final class IdentityReadinessHealthIndicator implements HealthIndicator {

	private final Supplier<IdentityReadiness> readiness;

	IdentityReadinessHealthIndicator(Supplier<IdentityReadiness> readiness) { this.readiness = readiness; }

	@Override
	public Health health() {
		try { this.readiness.get().requireReady(); return Health.up().build(); }
		catch (RuntimeException ex) { return Health.down().build(); }
	}
}
