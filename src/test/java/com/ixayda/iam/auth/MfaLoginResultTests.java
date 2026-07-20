package com.ixayda.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class MfaLoginResultTests {

	@Test
	void exposesAuthenticatedSession() {
		UserSession session = session();
		MfaLoginResult result = MfaLoginResult.authenticated(session);

		assertThat(result.status()).isEqualTo(MfaLoginStatus.AUTHENTICATED);
		assertThat(result.authenticated()).isTrue();
		assertThat(result.session()).contains(session);
	}

	@Test
	void exposesSharedFailuresWithoutSessions() {
		MfaLoginResult rejected = MfaLoginResult.rejected();
		MfaLoginResult unavailable = MfaLoginResult.unavailable();

		assertThat(rejected.status()).isEqualTo(MfaLoginStatus.REJECTED);
		assertThat(rejected.authenticated()).isFalse();
		assertThat(rejected.session()).isEmpty();
		assertThat(MfaLoginResult.rejected()).isSameAs(rejected);
		assertThat(unavailable.status()).isEqualTo(MfaLoginStatus.UNAVAILABLE);
		assertThat(unavailable.authenticated()).isFalse();
		assertThat(unavailable.session()).isEmpty();
		assertThat(MfaLoginResult.unavailable()).isSameAs(unavailable);
	}

	@Test
	void rejectsANullAuthenticatedSession() {
		assertThatThrownBy(() -> MfaLoginResult.authenticated(null))
			.isInstanceOf(NullPointerException.class);
	}

	private UserSession session() {
		Instant now = Instant.parse("2026-01-01T00:00:00Z");
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				0, 0, now, now.plusSeconds(3600));
	}

}
