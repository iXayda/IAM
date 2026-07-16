package com.ixayda.iam.authorization;

import java.io.Serial;
import java.util.Collection;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public final class AuthorizationUserAuthentication extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 1L;

	private final AuthorizationPrincipal principal;

	private AuthorizationUserAuthentication(AuthorizationPrincipal principal,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = Objects.requireNonNull(principal, "Authorization principal must not be null");
		super.setAuthenticated(true);
	}

	public static AuthorizationUserAuthentication authenticated(AuthorizationPrincipal principal,
			Collection<? extends GrantedAuthority> authorities) {
		Objects.requireNonNull(authorities, "Authorities must not be null");
		return new AuthorizationUserAuthentication(principal, authorities);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public AuthorizationPrincipal getPrincipal() {
		return this.principal;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		if (authenticated) {
			throw new IllegalArgumentException("Use authenticated() to create an authenticated principal");
		}
		super.setAuthenticated(false);
	}

}
