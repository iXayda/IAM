package com.ixayda.iam.authorization.internal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaFactor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

final class AuthorizationMfaAuthenticationConverter implements AuthenticationConverter {

	private final AuthorizationLoginDetailsSource detailsSource;

	AuthorizationMfaAuthenticationConverter(AuthorizationLoginDetailsSource detailsSource) {
		this.detailsSource = detailsSource;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null
				|| !(session.getAttribute(AuthorizationMfaLoginPageController.CHALLENGE_ATTRIBUTE) instanceof MfaChallenge challenge)) {
			throw invalidAttempt();
		}
		MfaFactor factor = factor(request.getParameter("factor"));
		String code = request.getParameter("code");
		if (code == null) {
			throw invalidAttempt();
		}
		AuthorizationMfaAuthenticationToken authentication =
				new AuthorizationMfaAuthenticationToken(challenge, factor, code);
		authentication.setDetails(this.detailsSource.buildDetails(request));
		return authentication;
	}

	private static MfaFactor factor(String value) {
		if ("totp".equals(value)) {
			return MfaFactor.TOTP;
		}
		if ("recovery_code".equals(value)) {
			return MfaFactor.RECOVERY_CODE;
		}
		throw invalidAttempt();
	}

	private static BadCredentialsException invalidAttempt() {
		return new BadCredentialsException("Invalid or expired multi-factor authentication attempt");
	}

}
