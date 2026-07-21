package com.ixayda.iam.account.internal;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;

@ConfigurationProperties("iam.account.mfa")
record AccountMfaProperties(Duration primaryAuthenticationValidDuration, String totpIssuer) {

	private static final Duration MINIMUM_VALID_DURATION = Duration.ofMinutes(1);

	private static final Duration MAXIMUM_VALID_DURATION = Duration.ofHours(1);

	AccountMfaProperties(@DefaultValue("5m") Duration primaryAuthenticationValidDuration,
			@DefaultValue("IAM") String totpIssuer) {
		this.primaryAuthenticationValidDuration = Objects.requireNonNull(primaryAuthenticationValidDuration,
				"Account MFA primary authentication valid duration must not be null");
		if (primaryAuthenticationValidDuration.compareTo(MINIMUM_VALID_DURATION) < 0
				|| primaryAuthenticationValidDuration.compareTo(MAXIMUM_VALID_DURATION) > 0) {
			throw new IllegalArgumentException(
					"Account MFA primary authentication valid duration must be between one minute and one hour");
		}
		Objects.requireNonNull(totpIssuer, "Account MFA TOTP issuer must not be null");
		this.totpIssuer = totpIssuer.trim();
		if (this.totpIssuer.isEmpty() || this.totpIssuer.length() > 64 || this.totpIssuer.indexOf(':') >= 0
				|| this.totpIssuer.chars().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException(
					"Account MFA TOTP issuer must contain between one and 64 visible characters without a colon");
		}
	}

	<T> AllRequiredFactorsAuthorizationManager<T> primaryAuthenticationAuthorizationManager() {
		return primaryAuthenticationAuthorizationManager(Clock.systemUTC());
	}

	<T> AllRequiredFactorsAuthorizationManager<T> primaryAuthenticationAuthorizationManager(Clock clock) {
		AllRequiredFactorsAuthorizationManager<T> manager = AllRequiredFactorsAuthorizationManager.<T>builder()
			.requireFactor((factor) -> factor.passwordAuthority().validDuration(this.primaryAuthenticationValidDuration))
			.build();
		manager.setClock(Objects.requireNonNull(clock, "Account MFA authorization clock must not be null"));
		return manager;
	}

}
