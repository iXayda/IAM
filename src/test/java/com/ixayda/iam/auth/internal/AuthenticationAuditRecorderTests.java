package com.ixayda.iam.auth.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditAuthenticationFactor;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuthenticationAuditRecorderTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00Z");

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f902");

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("remote:203.0.113.9");

	private final AuditEventOperations events = mock(AuditEventOperations.class);

	private final AuthenticationAuditRecorder recorder = new AuthenticationAuditRecorder(this.events,
			new AuthenticationTimeSource(Clock.fixed(NOW, ZoneOffset.UTC)));

	@Test
	void mapsAuthenticationOutcomesToBoundedAuditEvents() {
		MfaChallenge challenge = challenge();
		UserSession session = session();

		this.recorder.passwordFailed(TenantId.DEFAULT, null, SOURCE);
		this.recorder.mfaRequired(TenantId.DEFAULT, USER_ID, SOURCE, NOW.minusSeconds(1), challenge.factors());
		this.recorder.loginSucceeded(session, SOURCE, SessionAuthenticationFactorType.RECOVERY_CODE);
		this.recorder.loginThrottled(TenantId.DEFAULT, SOURCE, Duration.ofMillis(1));
		this.recorder.loginUnavailable(TenantId.DEFAULT, SOURCE, "rate_limit");
		this.recorder.mfaFailed(challenge, SOURCE, MfaFactor.RECOVERY_CODE, "invalid_code");
		this.recorder.mfaUnavailable(challenge, SOURCE, MfaFactor.RECOVERY_CODE, "challenge_state");

		ArgumentCaptor<AppendAuditEvent> events = ArgumentCaptor.forClass(AppendAuditEvent.class);
		verify(this.events, org.mockito.Mockito.times(7)).append(events.capture());
		assertThat(events.getAllValues()).extracting(event -> event.type().value()).containsExactly(
				"authentication.password.failed", "authentication.mfa.required",
				"authentication.login.succeeded", "authentication.login.throttled",
				"authentication.login.unavailable", "authentication.mfa.failed",
				"authentication.mfa.unavailable");
		assertThat(events.getAllValues()).extracting(AppendAuditEvent::outcome).containsExactly(
				AuditEventOutcome.FAILED, AuditEventOutcome.CHALLENGED, AuditEventOutcome.SUCCEEDED,
				AuditEventOutcome.THROTTLED, AuditEventOutcome.UNAVAILABLE, AuditEventOutcome.FAILED,
				AuditEventOutcome.UNAVAILABLE);
		assertThat(events.getAllValues()).allSatisfy(event -> assertThat(event.source()).isEqualTo(SOURCE.value()));
		assertThat(events.getAllValues().get(1).attributes()).containsEntry("available_factors", "recovery_code");
		assertThat(events.getAllValues().get(2).sessionId()).isEqualTo(session.id());
		assertThat(events.getAllValues().get(2).authenticationFactor())
			.isEqualTo(AuditAuthenticationFactor.RECOVERY_CODE);
		assertThat(events.getAllValues().get(3).attributes()).containsEntry("retry_after_seconds", "1");
	}

	private static MfaChallenge challenge() {
		return new MfaChallenge(MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				TenantId.DEFAULT, USER_ID, NOW.minusSeconds(1), NOW.plusSeconds(300),
				Set.of(MfaFactor.RECOVERY_CODE));
	}

	private static UserSession session() {
		return UserSession.start(SessionId.from("019f5aff-f979-7653-8001-67ea4274f903"), TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, NOW.minusSeconds(1)),
						new SessionAuthenticationFactor(SessionAuthenticationFactorType.RECOVERY_CODE, NOW)),
				0, 0, NOW, NOW.plusSeconds(3_600));
	}

}
