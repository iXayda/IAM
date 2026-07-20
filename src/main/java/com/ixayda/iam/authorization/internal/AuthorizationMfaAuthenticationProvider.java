package com.ixayda.iam.authorization.internal;

import java.util.Arrays;

import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.auth.MfaLoginOperations;
import com.ixayda.iam.auth.MfaLoginResult;
import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.session.UserSession;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;

final class AuthorizationMfaAuthenticationProvider implements AuthenticationProvider {

	private static final String INVALID_MFA = "Invalid or expired multi-factor authentication attempt";

	private final MfaLoginOperations logins;

	AuthorizationMfaAuthenticationProvider(MfaLoginOperations logins) {
		this.logins = logins;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		char[] rawCode = null;
		try {
			if (!(authentication instanceof AuthorizationMfaAuthenticationToken request)
					|| !(request.getDetails() instanceof AuthorizationLoginDetails details)
					|| !(request.getCredentials() instanceof String code)
					|| details.tenantId().isEmpty()
					|| !details.tenantId().orElseThrow().equals(request.challenge().tenantId())
					|| !request.challenge().supports(request.factor())) {
				throw badCredentials();
			}
			rawCode = code.toCharArray();
			MfaLoginResult result;
			try {
				result = complete(request, details, rawCode);
			}
			catch (IllegalArgumentException exception) {
				throw badCredentials();
			}
			return switch (result.status()) {
				case AUTHENTICATED -> authenticated(request, result.session().orElseThrow());
				case REJECTED -> throw badCredentials();
				case UNAVAILABLE -> throw new AuthenticationServiceException(
						"Multi-factor authentication is temporarily unavailable");
			};
		}
		finally {
			if (rawCode != null) {
				Arrays.fill(rawCode, '\0');
			}
			if (authentication instanceof CredentialsContainer credentials) {
				credentials.eraseCredentials();
			}
			if (authentication instanceof AbstractAuthenticationToken token) {
				token.setDetails(null);
			}
		}
	}

	private MfaLoginResult complete(AuthorizationMfaAuthenticationToken request, AuthorizationLoginDetails details,
			char[] rawCode) {
		if (request.factor() == MfaFactor.TOTP) {
			try (TotpCodeAttempt code = new TotpCodeAttempt(rawCode)) {
				return this.logins.complete(request.challenge(), details.source(), code);
			}
		}
		try (RecoveryCodeAttempt code = new RecoveryCodeAttempt(rawCode)) {
			return this.logins.complete(request.challenge(), details.source(), code);
		}
	}

	private static Authentication authenticated(AuthorizationMfaAuthenticationToken request, UserSession session) {
		if (!request.challenge().userId().equals(session.userId())) {
			throw new AuthenticationServiceException("MFA authentication returned a session for another user");
		}
		return AuthorizationUserAuthenticationFactory.fromPasswordSession(request.challenge().tenantId(), session);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthorizationMfaAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static BadCredentialsException badCredentials() {
		return new BadCredentialsException(INVALID_MFA);
	}

}
