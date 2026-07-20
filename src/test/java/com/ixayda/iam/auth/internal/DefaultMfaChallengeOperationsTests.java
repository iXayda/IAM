package com.ixayda.iam.auth.internal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeConsumeStatus;
import com.ixayda.iam.auth.MfaChallengeIssue;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.securitystate.SecurityStateConsumeStatus;
import com.ixayda.iam.securitystate.SecurityStateIssue;
import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateOperations;
import com.ixayda.iam.securitystate.SecurityStateToken;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultMfaChallengeOperationsTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00Z");

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274f902");

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("remote:203.0.113.9");

	private static final SecurityStateToken STATE_TOKEN =
			SecurityStateToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

	private final SecurityStateOperations states = mock(SecurityStateOperations.class);

	private final DefaultMfaChallengeOperations operations = new DefaultMfaChallengeOperations(this.states,
			new MfaChallengeProperties(Duration.ofMinutes(5)),
			new AuthenticationTimeSource(Clock.fixed(NOW, ZoneOffset.UTC)));

	@Test
	void issuesAndConsumesTheSameBoundChallengeMetadata() {
		when(this.states.issue(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
			.thenReturn(SecurityStateIssue.issued(STATE_TOKEN));
		MfaChallengeIssue issued = this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE, NOW.minusSeconds(1),
				Set.of(MfaFactor.TOTP, MfaFactor.RECOVERY_CODE));
		MfaChallenge challenge = issued.challenge().orElseThrow();
		ArgumentCaptor<SecurityStateKey> issuedKey = ArgumentCaptor.forClass(SecurityStateKey.class);
		verify(this.states).issue(issuedKey.capture(), org.mockito.ArgumentMatchers.eq(Duration.ofMinutes(5)));

		when(this.states.consume(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq(STATE_TOKEN)))
			.thenReturn(SecurityStateConsumeStatus.CONSUMED);
		assertThat(this.operations.consume(challenge, SOURCE)).isEqualTo(MfaChallengeConsumeStatus.CONSUMED);
		ArgumentCaptor<SecurityStateKey> consumedKey = ArgumentCaptor.forClass(SecurityStateKey.class);
		verify(this.states).consume(consumedKey.capture(), org.mockito.ArgumentMatchers.eq(STATE_TOKEN));

		assertThat(issuedKey.getValue()).isEqualTo(consumedKey.getValue());
		assertThat(issuedKey.getValue().purpose()).isEqualTo("mfa.login");
		assertThat(issuedKey.getValue().binding()).doesNotContain(SOURCE.value());
		assertThat(challenge.expiresAt()).isEqualTo(NOW.plusSeconds(300));
	}

	@Test
	void changesTheBindingForSourceAndMetadataTampering() {
		when(this.states.issue(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
			.thenReturn(SecurityStateIssue.issued(STATE_TOKEN));
		MfaChallenge challenge = this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE, NOW,
				Set.of(MfaFactor.TOTP)).challenge().orElseThrow();
		when(this.states.consume(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
			.thenReturn(SecurityStateConsumeStatus.REJECTED);

		this.operations.consume(challenge, LoginAttemptSource.trusted("remote:198.51.100.7"));
		MfaChallenge changed = new MfaChallenge(challenge.token(), challenge.tenantId(), challenge.userId(),
				challenge.passwordVerifiedAt(), challenge.expiresAt(), Set.of(MfaFactor.RECOVERY_CODE));
		this.operations.consume(changed, SOURCE);

		ArgumentCaptor<SecurityStateKey> keys = ArgumentCaptor.forClass(SecurityStateKey.class);
		verify(this.states, org.mockito.Mockito.times(2)).consume(keys.capture(), org.mockito.ArgumentMatchers.any());
		assertThat(keys.getAllValues()).doesNotHaveDuplicates();
	}

	@Test
	void mapsUnavailableAndRejectedStateOutcomes() {
		when(this.states.issue(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
			.thenReturn(SecurityStateIssue.unavailable());
		assertThat(this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE, NOW, Set.of(MfaFactor.TOTP)))
			.isSameAs(MfaChallengeIssue.unavailable());

		MfaChallenge challenge = new MfaChallenge(
				com.ixayda.iam.auth.MfaChallengeToken.from(STATE_TOKEN.value()), TenantId.DEFAULT, USER_ID, NOW,
				NOW.plusSeconds(300), Set.of(MfaFactor.TOTP));
		when(this.states.consume(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any()))
			.thenReturn(SecurityStateConsumeStatus.REJECTED, SecurityStateConsumeStatus.UNAVAILABLE);
		assertThat(this.operations.consume(challenge, SOURCE)).isEqualTo(MfaChallengeConsumeStatus.REJECTED);
		assertThat(this.operations.consume(challenge, SOURCE)).isEqualTo(MfaChallengeConsumeStatus.UNAVAILABLE);
	}

	@Test
	void rejectsPasswordVerificationTimesOutsideTheWindow() {
		assertThatThrownBy(() -> this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE, NOW.plusNanos(1),
				Set.of(MfaFactor.TOTP))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE,
				NOW.minus(Duration.ofMinutes(5)).minusNanos(1), Set.of(MfaFactor.TOTP)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.operations.issue(TenantId.DEFAULT, USER_ID, SOURCE, NOW, Set.of()))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
