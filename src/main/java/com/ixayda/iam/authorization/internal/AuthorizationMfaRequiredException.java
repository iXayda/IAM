package com.ixayda.iam.authorization.internal;

import com.ixayda.iam.auth.MfaChallenge;
import org.springframework.security.core.AuthenticationException;

final class AuthorizationMfaRequiredException extends AuthenticationException {

	private final MfaChallenge challenge;

	AuthorizationMfaRequiredException(MfaChallenge challenge) {
		super("Multi-factor authentication is required");
		this.challenge = challenge;
	}

	MfaChallenge challenge() {
		return this.challenge;
	}

}
