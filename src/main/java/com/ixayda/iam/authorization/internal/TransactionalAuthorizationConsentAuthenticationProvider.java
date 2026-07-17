package com.ixayda.iam.authorization.internal;

import java.util.Objects;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.transaction.support.TransactionOperations;

final class TransactionalAuthorizationConsentAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationProvider delegate;

	private final TransactionOperations transactions;

	TransactionalAuthorizationConsentAuthenticationProvider(AuthenticationProvider delegate,
			TransactionOperations transactions) {
		this.delegate = Objects.requireNonNull(delegate, "Authorization consent provider must not be null");
		this.transactions = Objects.requireNonNull(transactions, "Authorization consent transactions must not be null");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		ConsentOutcome outcome = Objects.requireNonNull(
				this.transactions.execute((status) -> authenticateInTransaction(authentication)),
				"Authorization consent transaction must return an outcome");
		if (outcome.denied() != null) {
			throw outcome.denied();
		}
		return outcome.authentication();
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return this.delegate.supports(authentication);
	}

	private ConsentOutcome authenticateInTransaction(Authentication authentication) {
		try {
			return new ConsentOutcome(this.delegate.authenticate(authentication), null);
		}
		catch (OAuth2AuthorizationCodeRequestAuthenticationException exception) {
			if (!OAuth2ErrorCodes.ACCESS_DENIED.equals(exception.getError().getErrorCode())) {
				throw exception;
			}
			return new ConsentOutcome(null, exception);
		}
	}

	private record ConsentOutcome(Authentication authentication,
			OAuth2AuthorizationCodeRequestAuthenticationException denied) {
	}

}
