package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;

class AuthorizationLocalPasswordAuthenticationProviderTests {

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("remote:203.0.113.8");

	private final LocalPasswordLoginOperations logins = mock(LocalPasswordLoginOperations.class);

	private final AuthorizationLocalPasswordAuthenticationProvider provider =
			new AuthorizationLocalPasswordAuthenticationProvider(this.logins);

	@Test
	void createsACredentialFreeAuthorizationPrincipalForACommittedSession() {
		UserSession session = session();
		when(this.logins.login(org.mockito.ArgumentMatchers.eq(TenantId.DEFAULT),
				org.mockito.ArgumentMatchers.eq(LoginKey.from("alice")), org.mockito.ArgumentMatchers.eq(SOURCE), any()))
			.thenReturn(LocalPasswordLoginResult.success(session));

		UsernamePasswordAuthenticationToken request = request("Alice", "candidate-password");
		Authentication authenticated = new ProviderManager(this.provider).authenticate(request);

		assertThat(authenticated).isInstanceOf(AuthorizationUserAuthentication.class);
		AuthorizationPrincipal principal = (AuthorizationPrincipal) authenticated.getPrincipal();
		assertThat(principal.tenantId()).isEqualTo(session.tenantId());
		assertThat(principal.userId()).isEqualTo(session.userId());
		assertThat(principal.sessionId()).isEqualTo(session.id());
		assertThat(authenticated.getCredentials()).isNull();
		assertThat(authenticated.getDetails()).isNull();
		assertThat(request.getCredentials()).isNull();
		assertThat(request.getDetails()).isNull();
		assertThat(authenticated.getAuthorities()).singleElement().isInstanceOfSatisfying(
				FactorGrantedAuthority.class, (factor) -> {
					assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
					assertThat(factor.getIssuedAt()).isEqualTo(session.authenticatedAt());
				});
		ArgumentCaptor<PasswordAttempt> attempt = ArgumentCaptor.forClass(PasswordAttempt.class);
		verify(this.logins).login(org.mockito.ArgumentMatchers.eq(TenantId.DEFAULT),
				org.mockito.ArgumentMatchers.eq(LoginKey.from("alice")), org.mockito.ArgumentMatchers.eq(SOURCE),
				attempt.capture());
		assertThat(attempt.getValue().isDestroyed()).isTrue();
	}

	@Test
	void mapsIndependentSessionFactorsToSpringSecurityAuthorities() {
		Instant passwordVerifiedAt = Instant.parse("2026-01-01T00:00:00Z");
		Instant totpVerifiedAt = passwordVerifiedAt.plusSeconds(30);
		Instant authenticatedAt = totpVerifiedAt.plusNanos(1);
		UserSession session = UserSession.start(
				SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, passwordVerifiedAt),
						new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, totpVerifiedAt)),
				0, 0, authenticatedAt, authenticatedAt.plus(Duration.ofHours(8)));
		when(this.logins.login(any(), any(), any(), any())).thenReturn(LocalPasswordLoginResult.success(session));

		Authentication authenticated = this.provider.authenticate(request("alice", "candidate-password"));

		assertThat(authenticated.getAuthorities()).hasSize(2)
			.anySatisfy(authority -> assertThat(authority).isInstanceOfSatisfying(FactorGrantedAuthority.class,
					factor -> {
						assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
						assertThat(factor.getIssuedAt()).isEqualTo(passwordVerifiedAt);
					}))
			.anySatisfy(authority -> assertThat(authority).isInstanceOfSatisfying(FactorGrantedAuthority.class,
					factor -> {
						assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.OTT_AUTHORITY);
						assertThat(factor.getIssuedAt()).isEqualTo(totpVerifiedAt);
					}));
	}

	@Test
	void rejectsSessionsOutsideTheRequestedTenantOrActiveState() {
		UserSession otherTenant = session(TenantId.random());
		UserSession active = session();
		UserSession revoked = active.revoke(active.authenticatedAt().plusSeconds(1));
		when(this.logins.login(any(), any(), any(), any()))
			.thenReturn(LocalPasswordLoginResult.success(otherTenant), LocalPasswordLoginResult.success(revoked));

		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "candidate-password")))
			.isInstanceOf(AuthenticationServiceException.class)
			.hasMessage("Local password authentication returned an invalid session");
		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "candidate-password")))
			.isInstanceOf(AuthenticationServiceException.class)
			.hasMessage("Local password authentication returned an invalid session");
	}

	@Test
	void erasesRequestCredentialsWhenAuthenticationFailsUnexpectedly() {
		IllegalStateException failure = new IllegalStateException("login dependency failed");
		when(this.logins.login(any(), any(), any(), any())).thenThrow(failure);
		UsernamePasswordAuthenticationToken request = request("alice", "candidate-password");

		assertThatThrownBy(() -> this.provider.authenticate(request)).isSameAs(failure);
		assertThat(request.getCredentials()).isNull();
		assertThat(request.getDetails()).isNull();
		ArgumentCaptor<PasswordAttempt> attempt = ArgumentCaptor.forClass(PasswordAttempt.class);
		verify(this.logins).login(org.mockito.ArgumentMatchers.eq(TenantId.DEFAULT),
				org.mockito.ArgumentMatchers.eq(LoginKey.from("alice")), org.mockito.ArgumentMatchers.eq(SOURCE),
				attempt.capture());
		assertThat(attempt.getValue().isDestroyed()).isTrue();
	}

	@Test
	void mapsRejectedThrottledAndUnavailableOutcomesToSpringSecurityFailures() {
		when(this.logins.login(any(), any(), any(), any()))
			.thenReturn(LocalPasswordLoginResult.rejected(), LocalPasswordLoginResult.throttled(Duration.ofSeconds(5)),
					LocalPasswordLoginResult.unavailable());

		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "wrong-password")))
			.isInstanceOf(BadCredentialsException.class);
		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "wrong-password")))
			.isInstanceOf(LockedException.class);
		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "wrong-password")))
			.isInstanceOf(AuthenticationServiceException.class);
	}

	@Test
	void preservesTheSourceBoundChallengeInAnMfaRequiredFailure() {
		MfaChallenge challenge = new MfaChallenge(
				MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), TenantId.DEFAULT,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63"),
				Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2026-01-01T00:05:00Z"),
				Set.of(MfaFactor.TOTP));
		when(this.logins.login(any(), any(), any(), any()))
			.thenReturn(LocalPasswordLoginResult.mfaRequired(challenge));

		assertThatThrownBy(() -> this.provider.authenticate(request("alice", "candidate-password")))
			.isInstanceOfSatisfying(AuthorizationMfaRequiredException.class,
					exception -> assertThat(exception.challenge()).isEqualTo(challenge))
			.hasMessage("Multi-factor authentication is required");
	}

	@Test
	void rejectsRequestsWithoutResolvedAuthorizationDetails() {
		UsernamePasswordAuthenticationToken request =
				UsernamePasswordAuthenticationToken.unauthenticated("alice", "candidate-password");
		request.setDetails(new AuthorizationLoginDetails(Optional.empty(), SOURCE));

		assertThatThrownBy(() -> this.provider.authenticate(request))
			.isInstanceOf(BadCredentialsException.class)
			.hasMessage("Invalid tenant, login, or password");
		verifyNoInteractions(this.logins);
	}

	@Test
	void supportsOnlyUsernamePasswordAuthentication() {
		assertThat(this.provider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
		assertThat(this.provider.supports(AuthorizationUserAuthentication.class)).isFalse();
	}

	private static UsernamePasswordAuthenticationToken request(String login, String password) {
		UsernamePasswordAuthenticationToken request =
				UsernamePasswordAuthenticationToken.unauthenticated(login, password);
		request.setDetails(new AuthorizationLoginDetails(Optional.of(TenantId.DEFAULT), SOURCE));
		return request;
	}

	private static UserSession session() {
		return session(TenantId.DEFAULT);
	}

	private static UserSession session(TenantId tenantId) {
		Instant authenticatedAt = Instant.parse("2026-01-01T00:00:00Z");
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), tenantId,
				UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62"), SessionAuthenticationMethod.PASSWORD,
				0, 0, authenticatedAt, authenticatedAt.plus(Duration.ofHours(8)));
	}

}
