package com.ixayda.iam.authorization.internal;

import java.util.List;
import java.util.Objects;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaFactor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.CredentialsContainer;

final class AuthorizationMfaAuthenticationToken extends AbstractAuthenticationToken implements CredentialsContainer {

	private final MfaChallenge challenge;

	private final MfaFactor factor;

	private String code;

	AuthorizationMfaAuthenticationToken(MfaChallenge challenge, MfaFactor factor, String code) {
		super(List.of());
		this.challenge = Objects.requireNonNull(challenge, "MFA challenge must not be null");
		this.factor = Objects.requireNonNull(factor, "MFA factor must not be null");
		this.code = Objects.requireNonNull(code, "MFA code must not be null");
		setAuthenticated(false);
	}

	MfaChallenge challenge() {
		return this.challenge;
	}

	MfaFactor factor() {
		return this.factor;
	}

	@Override
	public Object getCredentials() {
		return this.code;
	}

	@Override
	public Object getPrincipal() {
		return "mfa";
	}

	@Override
	public void eraseCredentials() {
		this.code = null;
	}

}
