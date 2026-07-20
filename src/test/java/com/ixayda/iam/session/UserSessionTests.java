package com.ixayda.iam.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class UserSessionTests {

	private static final SessionId SESSION_ID =
			SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e35");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e32");

	private static final Instant AUTHENTICATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final Instant EXPIRES_AT = AUTHENTICATED_AT.plusSeconds(8 * 60 * 60);

	@Test
	void startsAnActivePasswordSessionWithLifecycleSnapshots() {
		UserSession session = activeSession();

		assertThat(session.id()).isEqualTo(SESSION_ID);
		assertThat(session.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(session.userId()).isEqualTo(USER_ID);
		assertThat(session.authenticationMethod()).isEqualTo(SessionAuthenticationMethod.PASSWORD);
		assertThat(session.authenticationFactors()).containsExactly(
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, AUTHENTICATED_AT));
		assertThat(session.status()).isEqualTo(SessionStatus.ACTIVE);
		assertThat(session.issuedTenantVersion()).isEqualTo(2);
		assertThat(session.issuedUserVersion()).isEqualTo(7);
		assertThat(session.version()).isZero();
		assertThat(session.authenticatedAt()).isEqualTo(AUTHENTICATED_AT);
		assertThat(session.updatedAt()).isEqualTo(AUTHENTICATED_AT);
		assertThat(session.expiresAt()).isEqualTo(EXPIRES_AT);
		assertThat(session.revokedAt()).isNull();
	}

	@Test
	void evaluatesExpirationAtTheExactBoundary() {
		UserSession session = activeSession();

		assertThat(session.isExpiredAt(EXPIRES_AT.minusNanos(1))).isFalse();
		assertThat(session.isExpiredAt(EXPIRES_AT)).isTrue();
		assertThat(session.isRevoked()).isFalse();
		assertThatThrownBy(() -> session.isExpiredAt(null)).isInstanceOf(NullPointerException.class);
	}

	@Test
	void revokesAnActiveSessionIdempotently() {
		UserSession active = activeSession();
		Instant revokedAt = AUTHENTICATED_AT.plusSeconds(60);

		UserSession revoked = active.revoke(revokedAt);

		assertThat(revoked.status()).isEqualTo(SessionStatus.REVOKED);
		assertThat(revoked.version()).isOne();
		assertThat(revoked.updatedAt()).isEqualTo(revokedAt);
		assertThat(revoked.revokedAt()).isEqualTo(revokedAt);
		assertThat(revoked.isRevoked()).isTrue();
		assertThat(revoked.id()).isEqualTo(active.id());
		assertThat(revoked.tenantId()).isEqualTo(active.tenantId());
		assertThat(revoked.userId()).isEqualTo(active.userId());
		assertThat(revoked.authenticationFactors()).isEqualTo(active.authenticationFactors());
		assertThat(revoked.issuedTenantVersion()).isEqualTo(active.issuedTenantVersion());
		assertThat(revoked.issuedUserVersion()).isEqualTo(active.issuedUserVersion());
		assertThat(revoked.revoke(revokedAt.plusSeconds(1))).isSameAs(revoked);
	}

	@Test
	void keepsRevocationTimeMonotonicWhenTheClockMovesBackward() {
		UserSession active = activeSession();

		UserSession revoked = active.revoke(AUTHENTICATED_AT.minusSeconds(1));

		assertThat(revoked.updatedAt()).isEqualTo(AUTHENTICATED_AT);
		assertThat(revoked.revokedAt()).isEqualTo(AUTHENTICATED_AT);
	}

	@Test
	void rejectsInvalidStoredStateAndTransitions() {
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, -1, 7, 0, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, 2, -1, 0, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, 2, 7, -1, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, 2, 7, 0, AUTHENTICATED_AT,
				AUTHENTICATED_AT.minusSeconds(1), EXPIRES_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, 2, 7, 0, AUTHENTICATED_AT, AUTHENTICATED_AT,
				AUTHENTICATED_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.ACTIVE, 2, 7, 0, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, AUTHENTICATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.REVOKED, 2, 7, 1, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, null)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.REVOKED, 2, 7, 1, AUTHENTICATED_AT, AUTHENTICATED_AT,
				EXPIRES_AT, AUTHENTICATED_AT.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> session(SessionStatus.REVOKED, 2, 7, 1, AUTHENTICATED_AT,
				AUTHENTICATED_AT.plusSeconds(1), EXPIRES_AT, AUTHENTICATED_AT.plusSeconds(2)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void validatesAuthenticationFactorEvidence() {
		SessionAuthenticationFactor password =
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, AUTHENTICATED_AT);
		SessionAuthenticationFactor totp =
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, AUTHENTICATED_AT);
		SessionAuthenticationFactor earlierTotp =
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, AUTHENTICATED_AT.minusSeconds(1));

		UserSession session = UserSession.start(SESSION_ID, TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD, Set.of(password, totp), 2, 7, AUTHENTICATED_AT, EXPIRES_AT);

		assertThat(session.authenticationFactors()).containsExactlyInAnyOrder(password, totp);
		assertThatThrownBy(() -> UserSession.start(SESSION_ID, TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD, Set.of(totp), 2, 7, AUTHENTICATED_AT, EXPIRES_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> UserSession.start(SESSION_ID, TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD, Set.of(password, totp, earlierTotp), 2, 7,
				AUTHENTICATED_AT, EXPIRES_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> UserSession.start(SESSION_ID, TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD,
						AUTHENTICATED_AT.plusNanos(1))),
				2, 7, AUTHENTICATED_AT, EXPIRES_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD,
				Instant.EPOCH.minusNanos(1))).isInstanceOf(IllegalArgumentException.class);
	}

	private UserSession activeSession() {
		return UserSession.start(SESSION_ID, TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD, 2, 7,
				AUTHENTICATED_AT, EXPIRES_AT);
	}

	private UserSession session(SessionStatus status, long issuedTenantVersion, long issuedUserVersion, long version,
			Instant authenticatedAt, Instant updatedAt, Instant expiresAt, Instant revokedAt) {
		return new UserSession(SESSION_ID, TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, authenticatedAt)), status,
				issuedTenantVersion, issuedUserVersion, version, authenticatedAt, updatedAt, expiresAt, revokedAt);
	}

}
