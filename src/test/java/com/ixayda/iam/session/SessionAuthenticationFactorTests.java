package com.ixayda.iam.session;

import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SessionAuthenticationFactorTests {

	@Test
	void sessionsNormalizeIssuanceTimeAfterValidatingFactorOrder() {
		SessionAuthenticationFactor factor = new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP,
				Instant.parse("2026-01-01T00:00:00.123456789Z"));
		UserSession session = UserSession.start(SessionId.from("019f5aff-f979-7653-8001-67ea4274f903"),
				TenantId.DEFAULT, UserId.from("019f5aff-f979-7653-8001-67ea4274f904"),
				SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD,
						Instant.parse("2026-01-01T00:00:00Z")), factor),
				0, 0, Instant.parse("2026-01-01T00:00:01Z"), Instant.parse("2026-01-01T08:00:01Z"));

		assertThat(session.authenticationFactors())
			.filteredOn(candidate -> candidate.type() == SessionAuthenticationFactorType.TOTP)
			.singleElement()
			.extracting(SessionAuthenticationFactor::issuedAt)
			.isEqualTo(Instant.parse("2026-01-01T00:00:00.123456Z"));
	}

}
