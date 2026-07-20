package com.ixayda.iam.authorization;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;

@ConfigurationProperties("iam.admin.mfa")
public record AdminMfaPolicy(Duration validDuration) {

	private static final Duration MINIMUM_VALID_DURATION = Duration.ofMinutes(1);

	private static final Duration MAXIMUM_VALID_DURATION = Duration.ofHours(8);

	public AdminMfaPolicy(@DefaultValue("15m") Duration validDuration) {
		this.validDuration = Objects.requireNonNull(validDuration, "Admin MFA valid duration must not be null");
		if (validDuration.compareTo(MINIMUM_VALID_DURATION) < 0
				|| validDuration.compareTo(MAXIMUM_VALID_DURATION) > 0) {
			throw new IllegalArgumentException("Admin MFA valid duration must be between one minute and eight hours");
		}
	}

	public <T> AllRequiredFactorsAuthorizationManager<T> authorizationManager() {
		return authorizationManager(Clock.systemUTC());
	}

	<T> AllRequiredFactorsAuthorizationManager<T> authorizationManager(Clock clock) {
		AllRequiredFactorsAuthorizationManager<T> manager = AllRequiredFactorsAuthorizationManager.<T>builder()
			.requireFactor((factor) -> factor.passwordAuthority())
			.requireFactor((factor) -> factor.ottAuthority().validDuration(this.validDuration))
			.build();
		manager.setClock(Objects.requireNonNull(clock, "Admin MFA authorization clock must not be null"));
		return manager;
	}

}
