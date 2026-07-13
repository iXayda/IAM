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

class LocalPasswordLoginResultTests {

	@Test
	void exposesOnlySuccessOrFailureWithoutDiagnosticIdentityData() {
		UserSession session = session();
		LocalPasswordLoginResult success = LocalPasswordLoginResult.success(session);
		LocalPasswordLoginResult failure = LocalPasswordLoginResult.failure();

		assertThat(success.authenticated()).isTrue();
		assertThat(success.session()).contains(session);
		assertThat(success.toString()).isEqualTo("LocalPasswordLoginResult[authenticated=true]")
			.doesNotContain(session.id().toString(), session.userId().toString());
		assertThat(failure.authenticated()).isFalse();
		assertThat(failure.session()).isEmpty();
		assertThat(failure.toString()).isEqualTo("LocalPasswordLoginResult[authenticated=false]");
		assertThat(LocalPasswordLoginResult.failure()).isSameAs(failure);
		assertThatThrownBy(() -> LocalPasswordLoginResult.success(null))
			.isInstanceOf(NullPointerException.class);
	}

	private UserSession session() {
		Instant authenticatedAt = Instant.parse("2026-01-01T00:00:00Z");
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				0, 0, authenticatedAt, authenticatedAt.plusSeconds(60));
	}

}
