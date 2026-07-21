package com.ixayda.iam.account.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AccountMfaPropertiesTests {

	private static final Instant NOW = Instant.parse("2026-07-21T12:00:00Z");

	@Test
	void acceptsFiveMinutePolicyAndIamIssuer() {
		AccountMfaProperties properties = new AccountMfaProperties(Duration.ofMinutes(5), "IAM");

		assertThat(properties.primaryAuthenticationValidDuration()).isEqualTo(Duration.ofMinutes(5));
		assertThat(properties.totpIssuer()).isEqualTo("IAM");
	}

	@Test
	void requiresRecentPasswordAuthentication() {
		AccountMfaProperties properties = new AccountMfaProperties(Duration.ofMinutes(5), " Example IAM ");
		Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

		assertThat(granted(properties, authentication(NOW.minusSeconds(299)), clock)).isTrue();
		assertThat(granted(properties, authentication(NOW.minusSeconds(301)), clock)).isFalse();
		assertThat(properties.totpIssuer()).isEqualTo("Example IAM");
	}

	@Test
	void rejectsUnsafePolicyValues() {
		assertThatThrownBy(() -> new AccountMfaProperties(Duration.ofSeconds(59), "IAM"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AccountMfaProperties(Duration.ofHours(1).plusSeconds(1), "IAM"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AccountMfaProperties(Duration.ofMinutes(5), "issuer:name"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AccountMfaProperties(Duration.ofMinutes(5), " "))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private static boolean granted(AccountMfaProperties properties, AuthorizationUserAuthentication authentication,
			Clock clock) {
		AuthorizationResult result = properties.primaryAuthenticationAuthorizationManager(clock)
			.authorize(() -> authentication, new Object());
		return result != null && result.isGranted();
	}

	private static AuthorizationUserAuthentication authentication(Instant passwordAt) {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT,
				UserId.from("019f5aff-f979-7653-8001-67ea4274f901"),
				SessionId.from("019f5aff-f979-7653-8001-67ea4274f902"), SessionAuthenticationMethod.PASSWORD, NOW);
		return AuthorizationUserAuthentication.authenticated(principal,
				List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
					.issuedAt(passwordAt)
					.build()));
	}

}
