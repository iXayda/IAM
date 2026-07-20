package com.ixayda.iam.auth;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaChallengeValuesTests {

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f901");

	private static final Instant VERIFIED_AT = Instant.parse("2026-07-20T00:00:00Z");

	private static final MfaChallengeToken TOKEN =
			MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

	@Test
	void protectsTokenDiagnosticsAndCopiesFactors() {
		EnumSet<MfaFactor> factors = EnumSet.of(MfaFactor.TOTP, MfaFactor.RECOVERY_CODE);
		MfaChallenge challenge = challenge(factors);
		factors.clear();

		assertThat(challenge.factors()).containsExactlyInAnyOrder(MfaFactor.TOTP, MfaFactor.RECOVERY_CODE);
		assertThat(challenge.supports(MfaFactor.TOTP)).isTrue();
		assertThat(challenge.toString()).contains("token=redacted", "userId=redacted")
			.doesNotContain(TOKEN.value(), USER_ID.toString());
		assertThat(TOKEN.toString()).isEqualTo("MfaChallengeToken[redacted]");
	}

	@Test
	void rejectsMalformedTokensTimestampsAndFactors() {
		assertThatThrownBy(() -> MfaChallengeToken.from("short")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> MfaChallengeToken.from("!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new MfaChallenge(TOKEN, TenantId.DEFAULT, USER_ID, VERIFIED_AT,
				VERIFIED_AT, Set.of(MfaFactor.TOTP))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new MfaChallenge(TOKEN, TenantId.DEFAULT, USER_ID, VERIFIED_AT,
				VERIFIED_AT.plusSeconds(1), Set.of())).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void modelsIssuedAndUnavailableOutcomesWithoutLeakingTheChallenge() {
		MfaChallenge challenge = challenge(Set.of(MfaFactor.TOTP));
		MfaChallengeIssue issued = MfaChallengeIssue.issued(challenge);

		assertThat(issued.issued()).isTrue();
		assertThat(issued.challenge()).contains(challenge);
		assertThat(issued.toString()).doesNotContain(TOKEN.value());
		assertThat(MfaChallengeIssue.unavailable().issued()).isFalse();
		assertThat(MfaChallengeIssue.unavailable().challenge()).isEmpty();
	}

	private static MfaChallenge challenge(Set<MfaFactor> factors) {
		return new MfaChallenge(TOKEN, TenantId.DEFAULT, USER_ID, VERIFIED_AT, VERIFIED_AT.plusSeconds(300),
				factors);
	}

}
