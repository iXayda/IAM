package com.ixayda.iam.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import org.junit.jupiter.api.Test;

class LoginRateLimitValuesTests {

	@Test
	void validatesAndRedactsLoginAttemptSources() {
		LoginAttemptSource source = LoginAttemptSource.trusted("203.0.113.10");

		assertThat(source.value()).isEqualTo("203.0.113.10");
		assertThat(source).hasToString("LoginAttemptSource[redacted]");
		assertThatThrownBy(() -> LoginAttemptSource.trusted(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginAttemptSource.trusted("")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptSource.trusted("source with spaces"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptSource.trusted("a".repeat(LoginAttemptSource.MAX_LENGTH + 1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void validatesAndRedactsLoginAttemptKeys() {
		LoginAttemptSource source = LoginAttemptSource.trusted("203.0.113.10");
		LoginAttemptKey key = new LoginAttemptKey(TenantId.DEFAULT, LoginKey.from("alice"), source);

		assertThat(key).hasToString("LoginAttemptKey[tenantId=" + TenantId.DEFAULT
				+ ", loginKey=redacted, source=redacted]");
		assertThatThrownBy(() -> new LoginAttemptKey(null, LoginKey.from("alice"), source))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new LoginAttemptKey(TenantId.DEFAULT, null, source))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new LoginAttemptKey(TenantId.DEFAULT, LoginKey.from("alice"), null))
			.isInstanceOf(NullPointerException.class);
	}

	@Test
	void representsAllowedThrottledAndUnavailableDecisions() {
		LoginAttemptLease lease = LoginAttemptLease.from("AAAAAAAAAAAAAAAAAAAAAA");
		LoginAttemptDecision allowed = LoginAttemptDecision.allowed(lease);
		LoginAttemptDecision throttled = LoginAttemptDecision.throttled(Duration.ofSeconds(30));
		LoginAttemptDecision unavailable = LoginAttemptDecision.unavailable();

		assertThat(allowed.status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(allowed.isAllowed()).isTrue();
		assertThat(allowed.retryAfter()).isEmpty();
		assertThat(allowed.lease()).contains(lease);
		assertThat(throttled.status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		assertThat(throttled.isAllowed()).isFalse();
		assertThat(throttled.retryAfter()).contains(Duration.ofSeconds(30));
		assertThat(throttled.lease()).isEmpty();
		assertThat(unavailable.status()).isEqualTo(LoginAttemptStatus.UNAVAILABLE);
		assertThat(unavailable.retryAfter()).isEmpty();
		assertThat(unavailable.lease()).isEmpty();
		assertThat(unavailable).hasToString("LoginAttemptDecision[status=UNAVAILABLE]");
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(Duration.ofMillis(-1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptDecision.allowed(null)).isInstanceOf(NullPointerException.class);
	}

	@Test
	void validatesAndRedactsLoginAttemptLeases() {
		LoginAttemptLease lease = LoginAttemptLease.from("AAAAAAAAAAAAAAAAAAAAAA");

		assertThat(lease.value()).isEqualTo("AAAAAAAAAAAAAAAAAAAAAA");
		assertThat(lease).hasToString("LoginAttemptLease[redacted]");
		assertThatThrownBy(() -> LoginAttemptLease.from(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginAttemptLease.from("too-short"))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
