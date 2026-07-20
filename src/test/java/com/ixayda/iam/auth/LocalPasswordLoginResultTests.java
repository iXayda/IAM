package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class LocalPasswordLoginResultTests {

	@Test
	void exposesAuthenticatedAndRejectedOutcomesWithoutIdentityData() {
		UserSession session = session();
		LocalPasswordLoginResult authenticated = LocalPasswordLoginResult.success(session);
		LocalPasswordLoginResult rejected = LocalPasswordLoginResult.rejected();

		assertThat(authenticated.status()).isEqualTo(LocalPasswordLoginStatus.AUTHENTICATED);
		assertThat(authenticated.authenticated()).isTrue();
		assertThat(authenticated.session()).contains(session);
		assertThat(authenticated.retryAfter()).isEmpty();
		assertThat(authenticated.toString()).isEqualTo("LocalPasswordLoginResult[status=AUTHENTICATED]")
			.doesNotContain(session.id().toString(), session.userId().toString());
		assertThat(rejected.status()).isEqualTo(LocalPasswordLoginStatus.REJECTED);
		assertThat(rejected.authenticated()).isFalse();
		assertThat(rejected.session()).isEmpty();
		assertThat(rejected.retryAfter()).isEmpty();
		assertThat(LocalPasswordLoginResult.rejected()).isSameAs(rejected);
	}

	@Test
	void exposesThrottledAndUnavailableOutcomesWithoutRateLimitDetailsInDiagnostics() {
		Duration retryAfter = Duration.ofSeconds(17);
		LocalPasswordLoginResult throttled = LocalPasswordLoginResult.throttled(retryAfter);
		LocalPasswordLoginResult unavailable = LocalPasswordLoginResult.unavailable();

		assertThat(throttled.status()).isEqualTo(LocalPasswordLoginStatus.THROTTLED);
		assertThat(throttled.authenticated()).isFalse();
		assertThat(throttled.session()).isEmpty();
		assertThat(throttled.retryAfter()).contains(retryAfter);
		assertThat(throttled.toString()).isEqualTo("LocalPasswordLoginResult[status=THROTTLED]")
			.doesNotContain("17");
		assertThat(unavailable.status()).isEqualTo(LocalPasswordLoginStatus.UNAVAILABLE);
		assertThat(unavailable.session()).isEmpty();
		assertThat(unavailable.retryAfter()).isEmpty();
		assertThat(LocalPasswordLoginResult.unavailable()).isSameAs(unavailable);
	}

	@Test
	void exposesMfaRequiredWithoutSessionOrBearerDiagnostics() {
		MfaChallenge challenge = new MfaChallenge(
				MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63"),
				Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-01T00:05:00Z"),
				Set.of(MfaFactor.TOTP));
		LocalPasswordLoginResult required = LocalPasswordLoginResult.mfaRequired(challenge);

		assertThat(required.status()).isEqualTo(LocalPasswordLoginStatus.MFA_REQUIRED);
		assertThat(required.mfaRequired()).isTrue();
		assertThat(required.authenticated()).isFalse();
		assertThat(required.session()).isEmpty();
		assertThat(required.challenge()).contains(challenge);
		assertThat(required.retryAfter()).isEmpty();
		assertThat(required.toString()).doesNotContain(challenge.token().value());
	}

	@Test
	void rejectsInvalidFactoryArguments() {
		assertThatThrownBy(() -> LocalPasswordLoginResult.success(null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LocalPasswordLoginResult.mfaRequired(null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LocalPasswordLoginResult.throttled(null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LocalPasswordLoginResult.throttled(Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LocalPasswordLoginResult.throttled(Duration.ofSeconds(-1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private UserSession session() {
		Instant authenticatedAt = Instant.parse("2026-01-01T00:00:00Z");
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				0, 0, authenticatedAt, authenticatedAt.plusSeconds(60));
	}

}
