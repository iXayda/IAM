package com.ixayda.iam.credential;

import java.time.Instant;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpCredentialTests {

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f201");

	private static final Instant CREATED_AT = Instant.parse("2026-07-20T00:00:00Z");

	@Test
	void activatesAcceptsNewTimeStepsAndRevokesMonotonically() {
		TotpCredential pending = TotpCredential.pending(TenantId.DEFAULT, USER_ID, CREATED_AT,
				CREATED_AT.plusSeconds(600));

		assertThat(pending.status()).isEqualTo(TotpCredentialStatus.PENDING);
		assertThat(pending.isPendingAt(CREATED_AT.plusSeconds(599))).isTrue();
		assertThat(pending.isPendingAt(CREATED_AT.plusSeconds(600))).isFalse();

		TotpCredential active = pending.activate(100, CREATED_AT.plusSeconds(30));
		TotpCredential verified = active.accept(101, CREATED_AT.plusSeconds(60));
		TotpCredential revoked = verified.revoke(CREATED_AT.plusSeconds(59));

		assertThat(active.status()).isEqualTo(TotpCredentialStatus.ACTIVE);
		assertThat(active.version()).isOne();
		assertThat(active.lastAcceptedTimeStep()).isEqualTo(100);
		assertThat(verified.version()).isEqualTo(2);
		assertThat(verified.lastAcceptedTimeStep()).isEqualTo(101);
		assertThat(revoked.status()).isEqualTo(TotpCredentialStatus.REVOKED);
		assertThat(revoked.version()).isEqualTo(3);
		assertThat(revoked.updatedAt()).isEqualTo(verified.updatedAt());
		assertThat(revoked.revokedAt()).isEqualTo(verified.updatedAt());
		assertThat(revoked.revoke(CREATED_AT.plusSeconds(90))).isSameAs(revoked);
	}

	@Test
	void rejectsExpiredEnrollmentAndReplayedOrRegressedTimeSteps() {
		TotpCredential pending = TotpCredential.pending(TenantId.DEFAULT, USER_ID, CREATED_AT,
				CREATED_AT.plusSeconds(60));

		assertThatThrownBy(() -> pending.activate(100, CREATED_AT.plusSeconds(60)))
			.isInstanceOf(IllegalStateException.class);
		TotpCredential active = pending.activate(100, CREATED_AT.plusSeconds(30));
		assertThatThrownBy(() -> active.accept(100, CREATED_AT.plusSeconds(31)))
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> active.accept(99, CREATED_AT.plusSeconds(31)))
			.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> active.accept(101, CREATED_AT.plusSeconds(29)))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void rejectsInvalidStoredLifecycleAndParameters() {
		TotpCredentialId id = TotpCredentialId.random();
		assertThatThrownBy(() -> new TotpCredential(id, TenantId.DEFAULT, USER_ID, TotpCredentialStatus.PENDING,
				TotpAlgorithm.SHA1, 8, 30, null, 0, CREATED_AT, CREATED_AT, CREATED_AT.plusSeconds(60), null,
				null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpCredential(id, TenantId.DEFAULT, USER_ID, TotpCredentialStatus.ACTIVE,
				TotpAlgorithm.SHA1, 6, 30, 100L, 0, CREATED_AT, CREATED_AT.plusSeconds(30), null,
				CREATED_AT.plusSeconds(30), null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new TotpCredential(id, TenantId.DEFAULT, USER_ID, TotpCredentialStatus.REVOKED,
				TotpAlgorithm.SHA1, 6, 30, 100L, 2, CREATED_AT, CREATED_AT.plusSeconds(60), null, null,
				CREATED_AT.plusSeconds(60))).isInstanceOf(IllegalArgumentException.class);
	}

}
