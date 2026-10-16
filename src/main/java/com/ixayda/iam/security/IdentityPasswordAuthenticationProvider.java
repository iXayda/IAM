package com.ixayda.iam.security;

import java.util.List;
import java.util.Optional;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.service.IdentityAuthentications;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Framework adapter; the database decision must commit before a denial becomes an exception. */
@Component
public class IdentityPasswordAuthenticationProvider implements AuthenticationProvider {

	private final IdentityAuthentications authentications;

	IdentityPasswordAuthenticationProvider(IdentityAuthentications authentications) {
		this.authentications = authentications;
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof UsernamePasswordAuthenticationToken request)) {
			return null;
		}
		try {
			if (TransactionSynchronizationManager.isActualTransactionActive()) {
				throw new AuthenticationServiceException("Password authentication requires an independent transaction");
			}
			if (!(request.getDetails() instanceof PasswordAuthenticationContext context)) {
				throw new AuthenticationServiceException("Trusted authentication context is required");
			}
			String username = request.getPrincipal() instanceof String value ? value : null;
			String password = request.getCredentials() instanceof String value ? value : null;
			Optional<IdentityUser> user;
			try {
				user = this.authentications.authenticate(username, password, context);
			}
			catch (RuntimeException ex) {
				throw new AuthenticationServiceException("Password authentication is unavailable", ex);
			}
			if (user.isEmpty()) {
				throw new BadCredentialsException("Invalid credentials");
			}
			return UsernamePasswordAuthenticationToken.authenticated(user.orElseThrow().id(), null, List.of());
		}
		finally {
			request.eraseCredentials();
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
