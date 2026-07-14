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
		LoginAttemptSource source = LoginAttemptSource.from("203.0.113.10");

		assertThat(source.value()).isEqualTo("203.0.113.10");
		assertThat(source).hasToString("LoginAttemptSource[redacted]");
		assertThatThrownBy(() -> LoginAttemptSource.from(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginAttemptSource.from("")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptSource.from("source with spaces"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptSource.from("a".repeat(LoginAttemptSource.MAX_LENGTH + 1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void validatesAndRedactsLoginAttemptKeys() {
		LoginAttemptSource source = LoginAttemptSource.from("203.0.113.10");
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
		LoginAttemptDecision allowed = LoginAttemptDecision.allowed();
		LoginAttemptDecision throttled = LoginAttemptDecision.throttled(Duration.ofSeconds(30));
		LoginAttemptDecision unavailable = LoginAttemptDecision.unavailable();

		assertThat(allowed.status()).isEqualTo(LoginAttemptStatus.ALLOWED);
		assertThat(allowed.isAllowed()).isTrue();
		assertThat(allowed.retryAfter()).isEmpty();
		assertThat(throttled.status()).isEqualTo(LoginAttemptStatus.THROTTLED);
		assertThat(throttled.isAllowed()).isFalse();
		assertThat(throttled.retryAfter()).contains(Duration.ofSeconds(30));
		assertThat(unavailable.status()).isEqualTo(LoginAttemptStatus.UNAVAILABLE);
		assertThat(unavailable.retryAfter()).isEmpty();
		assertThat(unavailable).hasToString("LoginAttemptDecision[status=UNAVAILABLE]");
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(Duration.ZERO))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginAttemptDecision.throttled(Duration.ofMillis(-1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
