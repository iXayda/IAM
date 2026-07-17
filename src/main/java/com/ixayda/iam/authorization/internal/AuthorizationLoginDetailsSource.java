package com.ixayda.iam.authorization.internal;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.tenant.TenantId;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

@Component
final class AuthorizationLoginDetailsSource
		implements AuthenticationDetailsSource<HttpServletRequest, AuthorizationLoginDetails> {

	static final String SAVED_REQUEST_ATTRIBUTE = "IAM_AUTHORIZATION_SAVED_REQUEST";

	private static final LoginAttemptSource UNKNOWN_SOURCE = LoginAttemptSource.trusted("remote:unknown");

	private final ClientOperations clients;

	AuthorizationLoginDetailsSource(ClientOperations clients) {
		this.clients = clients;
	}

	@Override
	public AuthorizationLoginDetails buildDetails(HttpServletRequest request) {
		return new AuthorizationLoginDetails(resolveTenant(request), source(request));
	}

	private Optional<TenantId> resolveTenant(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null || !(session.getAttribute(SAVED_REQUEST_ATTRIBUTE) instanceof SavedRequest savedRequest)
				|| !"GET".equals(savedRequest.getMethod())) {
			return Optional.empty();
		}
		String[] clientIdentifiers = savedRequest.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
		if (clientIdentifiers == null || clientIdentifiers.length != 1) {
			return Optional.empty();
		}
		try {
			return this.clients.findActiveByIdentifier(new ClientIdentifier(clientIdentifiers[0]))
				.map((client) -> client.tenantId());
		}
		catch (IllegalArgumentException exception) {
			return Optional.empty();
		}
	}

	private static LoginAttemptSource source(HttpServletRequest request) {
		String remoteAddress = request.getRemoteAddr();
		if (remoteAddress == null || remoteAddress.isEmpty() || remoteAddress.length() > 128
				|| !remoteAddress.chars().allMatch((character) -> character >= 0x21 && character <= 0x7e)) {
			return UNKNOWN_SOURCE;
		}
		return LoginAttemptSource.trusted("remote:" + remoteAddress);
	}

}
