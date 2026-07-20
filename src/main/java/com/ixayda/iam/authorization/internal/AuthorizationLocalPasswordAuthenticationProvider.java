package com.ixayda.iam.authorization.internal;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.ixayda.iam.auth.LocalPasswordLoginOperations;
import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionStatus;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.authority.FactorGrantedAuthority;

final class AuthorizationLocalPasswordAuthenticationProvider implements AuthenticationProvider {

	private static final String INVALID_CREDENTIALS = "Invalid tenant, login, or password";

	private final LocalPasswordLoginOperations logins;

	AuthorizationLocalPasswordAuthenticationProvider(LocalPasswordLoginOperations logins) {
		this.logins = logins;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		char[] rawPassword = null;
		try {
			if (!(authentication.getDetails() instanceof AuthorizationLoginDetails details)
					|| !(authentication.getPrincipal() instanceof String login)
					|| !(authentication.getCredentials() instanceof String password)) {
				throw badCredentials();
			}
			TenantId tenantId = details.tenantId()
				.orElseThrow(AuthorizationLocalPasswordAuthenticationProvider::badCredentials);
			LoginKey loginKey;
			try {
				loginKey = LoginKey.from(login);
			}
			catch (IllegalArgumentException exception) {
				throw badCredentials();
			}
			rawPassword = password.toCharArray();
			if (rawPassword.length == 0 || rawPassword.length > PasswordAttempt.MAX_LENGTH) {
				throw badCredentials();
			}
			try (PasswordAttempt passwordAttempt = new PasswordAttempt(rawPassword)) {
				LocalPasswordLoginResult result = this.logins.login(tenantId, loginKey, details.source(), passwordAttempt);
				return switch (result.status()) {
					case AUTHENTICATED -> authenticated(tenantId, result.session().orElseThrow());
					case MFA_REQUIRED -> throw new AuthorizationMfaRequiredException(
							result.challenge().orElseThrow());
					case REJECTED -> throw badCredentials();
					case THROTTLED -> throw new LockedException("Local password authentication is temporarily throttled");
					case UNAVAILABLE -> throw new AuthenticationServiceException(
							"Local password authentication is temporarily unavailable");
				};
			}
		}
		finally {
			if (rawPassword != null) {
				Arrays.fill(rawPassword, '\0');
			}
			if (authentication instanceof CredentialsContainer credentials) {
				credentials.eraseCredentials();
			}
			if (authentication instanceof AbstractAuthenticationToken token) {
				token.setDetails(null);
			}
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static AuthorizationUserAuthentication authenticated(TenantId tenantId, UserSession session) {
		if (!tenantId.equals(session.tenantId())
				|| session.authenticationMethod() != SessionAuthenticationMethod.PASSWORD
				|| session.status() != SessionStatus.ACTIVE) {
			throw new AuthenticationServiceException("Local password authentication returned an invalid session");
		}
		AuthorizationPrincipal principal = new AuthorizationPrincipal(session.tenantId(), session.userId(), session.id(),
				session.authenticationMethod(), session.authenticatedAt());
		Map<String, Instant> factorTimes = new LinkedHashMap<>();
		session.authenticationFactors().forEach(factor -> factorTimes.merge(authority(factor.type()),
				factor.issuedAt(), (first, second) -> first.isAfter(second) ? first : second));
		List<FactorGrantedAuthority> authorities = factorTimes.entrySet().stream()
			.map(entry -> FactorGrantedAuthority.withAuthority(entry.getKey()).issuedAt(entry.getValue()).build())
			.toList();
		return AuthorizationUserAuthentication.authenticated(principal, authorities);
	}

	private static String authority(SessionAuthenticationFactorType factor) {
		return switch (factor) {
			case PASSWORD -> FactorGrantedAuthority.PASSWORD_AUTHORITY;
			case TOTP, RECOVERY_CODE -> FactorGrantedAuthority.OTT_AUTHORITY;
		};
	}

	private static BadCredentialsException badCredentials() {
		return new BadCredentialsException(INVALID_CREDENTIALS);
	}

}
