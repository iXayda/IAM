package com.ixayda.iam.authorization;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AdminMfaPolicyTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00Z");

	private static final Duration VALID_DURATION = Duration.ofMinutes(15);

	@Test
	void requiresARecentOneTimeTokenFactor() {
		AdminMfaPolicy policy = new AdminMfaPolicy(VALID_DURATION);
		var manager = policy.authorizationManager(Clock.fixed(NOW, ZoneOffset.UTC));

		assertThat(manager.authorize(() -> authentication(NOW.minus(VALID_DURATION).plusNanos(1)), new Object())
			.isGranted()).isTrue();
		assertThat(manager.authorize(() -> authentication(NOW.minus(VALID_DURATION)), new Object()).isGranted())
			.isFalse();
		assertThat(manager.authorize(() -> authentication(null), new Object()).isGranted()).isFalse();
		assertThat(manager.authorize(() -> secondFactorOnly(NOW.minusSeconds(60)), new Object()).isGranted())
			.isFalse();
	}

	@Test
	void boundsTheConfiguredValidityWindow() {
		assertThatThrownBy(() -> new AdminMfaPolicy(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new AdminMfaPolicy(Duration.ofSeconds(59)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new AdminMfaPolicy(Duration.ofHours(8).plusNanos(1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThat(new AdminMfaPolicy(Duration.ofMinutes(1)).validDuration()).isEqualTo(Duration.ofMinutes(1));
		assertThat(new AdminMfaPolicy(Duration.ofHours(8)).validDuration()).isEqualTo(Duration.ofHours(8));
	}

	private static AuthorizationUserAuthentication authentication(Instant secondFactorAt) {
		FactorGrantedAuthority password = FactorGrantedAuthority
			.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.issuedAt(NOW.minusSeconds(3_600))
			.build();
		if (secondFactorAt == null) {
			return AuthorizationUserAuthentication.authenticated(principal(), List.of(password));
		}
		return AuthorizationUserAuthentication.authenticated(principal(),
				List.of(password, FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.OTT_AUTHORITY)
					.issuedAt(secondFactorAt).build()));
	}

	private static AuthorizationUserAuthentication secondFactorOnly(Instant issuedAt) {
		return AuthorizationUserAuthentication.authenticated(principal(),
				List.of(FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.OTT_AUTHORITY)
					.issuedAt(issuedAt).build()));
	}

	private static AuthorizationPrincipal principal() {
		return new AuthorizationPrincipal(TenantId.DEFAULT,
				UserId.from("019f5aff-f979-7653-8001-67ea4274f902"),
				SessionId.from("019f5aff-f979-7653-8001-67ea4274f903"), SessionAuthenticationMethod.PASSWORD, NOW);
	}

}
