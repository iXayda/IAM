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

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaChallengeToken;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginOperations;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;

class AuthorizationMfaAuthenticationProviderTests {

	private static final LoginAttemptSource SOURCE = LoginAttemptSource.trusted("remote:203.0.113.8");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62");

	private static final Instant PASSWORD_VERIFIED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final MfaLoginOperations logins = mock(MfaLoginOperations.class);

	private final AuthorizationMfaAuthenticationProvider provider =
			new AuthorizationMfaAuthenticationProvider(this.logins);

	@Test
	void completesTotpAndReturnsTheCommittedMultiFactorSession() {
		Instant totpVerifiedAt = PASSWORD_VERIFIED_AT.plusSeconds(30);
		UserSession session = session(USER_ID, totpVerifiedAt);
		when(this.logins.complete(any(), any(), any(TotpCodeAttempt.class)))
			.thenReturn(MfaLoginResult.authenticated(session));
		AuthorizationMfaAuthenticationToken request = request(challenge(USER_ID), MfaFactor.TOTP, "123456");

		Authentication authenticated = this.provider.authenticate(request);

		assertThat(authenticated).isInstanceOf(AuthorizationUserAuthentication.class);
		assertThat(authenticated.getPrincipal()).isInstanceOfSatisfying(AuthorizationPrincipal.class,
				principal -> assertThat(principal.userId()).isEqualTo(USER_ID));
		assertThat(authenticated.getAuthorities()).hasSize(2)
			.anySatisfy(authority -> assertThat(authority).isInstanceOfSatisfying(FactorGrantedAuthority.class,
					factor -> assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY)))
			.anySatisfy(authority -> assertThat(authority).isInstanceOfSatisfying(FactorGrantedAuthority.class,
					factor -> {
						assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.OTT_AUTHORITY);
						assertThat(factor.getIssuedAt()).isEqualTo(totpVerifiedAt);
					}));
		assertThat(request.getCredentials()).isNull();
		assertThat(request.getDetails()).isNull();
		ArgumentCaptor<TotpCodeAttempt> code = ArgumentCaptor.forClass(TotpCodeAttempt.class);
		verify(this.logins).complete(org.mockito.ArgumentMatchers.eq(challenge(USER_ID)),
				org.mockito.ArgumentMatchers.eq(SOURCE), code.capture());
		assertThat(code.getValue().isDestroyed()).isTrue();
	}

	@Test
	void mapsRejectedUnavailableAndMalformedCodesToCredentialFailures() {
		when(this.logins.complete(any(), any(), any(TotpCodeAttempt.class)))
			.thenReturn(MfaLoginResult.rejected(), MfaLoginResult.unavailable());

		assertThatThrownBy(() -> this.provider.authenticate(request(challenge(USER_ID), MfaFactor.TOTP, "123456")))
			.isInstanceOf(BadCredentialsException.class);
		assertThatThrownBy(() -> this.provider.authenticate(request(challenge(USER_ID), MfaFactor.TOTP, "123456")))
			.isInstanceOf(AuthenticationServiceException.class);
		assertThatThrownBy(() -> this.provider.authenticate(request(challenge(USER_ID), MfaFactor.TOTP, "invalid")))
			.isInstanceOf(BadCredentialsException.class);
	}

	@Test
	void rejectsMismatchedRequestStateAndReturnedIdentity() {
		TenantId otherTenant = TenantId.random();
		AuthorizationMfaAuthenticationToken mismatchedTenant =
				request(challenge(USER_ID), MfaFactor.TOTP, "123456");
		mismatchedTenant.setDetails(new AuthorizationLoginDetails(Optional.of(otherTenant), SOURCE));

		assertThatThrownBy(() -> this.provider.authenticate(mismatchedTenant))
			.isInstanceOf(BadCredentialsException.class);
		verifyNoInteractions(this.logins);

		UserId otherUser = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e63");
		when(this.logins.complete(any(), any(), any(TotpCodeAttempt.class)))
			.thenReturn(MfaLoginResult.authenticated(session(otherUser, PASSWORD_VERIFIED_AT.plusSeconds(30))));

		assertThatThrownBy(() -> this.provider.authenticate(request(challenge(USER_ID), MfaFactor.TOTP, "123456")))
			.isInstanceOf(AuthenticationServiceException.class)
			.hasMessage("MFA authentication returned a session for another user");
	}

	@Test
	void supportsOnlyMfaAuthenticationRequests() {
		assertThat(this.provider.supports(AuthorizationMfaAuthenticationToken.class)).isTrue();
		assertThat(this.provider.supports(AuthorizationUserAuthentication.class)).isFalse();
	}

	private static AuthorizationMfaAuthenticationToken request(MfaChallenge challenge, MfaFactor factor, String code) {
		AuthorizationMfaAuthenticationToken request = new AuthorizationMfaAuthenticationToken(challenge, factor, code);
		request.setDetails(new AuthorizationLoginDetails(Optional.of(challenge.tenantId()), SOURCE));
		return request;
	}

	private static MfaChallenge challenge(UserId userId) {
		return new MfaChallenge(MfaChallengeToken.from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
				TenantId.DEFAULT, userId, PASSWORD_VERIFIED_AT, PASSWORD_VERIFIED_AT.plusSeconds(300),
				Set.of(MfaFactor.TOTP));
	}

	private static UserSession session(UserId userId, Instant totpVerifiedAt) {
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT, userId,
				SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, PASSWORD_VERIFIED_AT),
						new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, totpVerifiedAt)),
				0, 0, totpVerifiedAt, totpVerifiedAt.plus(Duration.ofHours(8)));
	}

}
