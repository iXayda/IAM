package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityProtocolClients;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.util.Assert;

/** Explicit native authentication adapter; the grant workflow must revalidate its captured snapshot. */
public final class IdentityClientAuthenticationProvider implements AuthenticationProvider {

	private final IdentityProtocolClients clients;
	private final OAuth2AuthorizationService authorizations;

	public IdentityClientAuthenticationProvider(IdentityProtocolClients clients, OAuth2AuthorizationService authorizations) {
		Assert.notNull(clients, "Protocol clients are required");
		Assert.notNull(authorizations, "Protected authorization service is required");
		this.clients = clients;
		this.authorizations = authorizations;
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OAuth2ClientAuthenticationToken request)) { return null; }
		try {
			if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(request.getClientAuthenticationMethod())) { throw failure("invalid_client"); }
			var snapshot = this.clients.findActiveById((String) request.getPrincipal()).orElseThrow(() -> failure("invalid_client"));
			var nativeProvider = new ClientSecretAuthenticationProvider(IdentityRegisteredClientRepository.pinned(snapshot), this.authorizations);
			nativeProvider.setPasswordEncoder(this.clients.secretVerifier());
			var verified = (OAuth2ClientAuthenticationToken) nativeProvider.authenticate(request);
			if (verified == null || !verified.isAuthenticated() || !snapshot.registration().equals(verified.getRegisteredClient())) { throw failure("server_error"); }
			// The framework's successful token retains the presented secret. Do not carry it into a grant context.
			var result = new OAuth2ClientAuthenticationToken(snapshot.registration(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
			result.setDetails(snapshot);
			return result;
		}
		catch (OAuth2AuthenticationException ex) {
			String code = ex.getError().getErrorCode();
			throw failure("invalid_client".equals(code) || "invalid_grant".equals(code) ? code : "server_error");
		}
		catch (RuntimeException ex) { throw failure("server_error"); }
	}

	@Override
	public boolean supports(Class<?> authentication) { return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication); }

	private static OAuth2AuthenticationException failure(String code) {
		String description = switch (code) {
			case "invalid_client" -> "Client authentication failed";
			case "invalid_grant" -> "Authorization grant is invalid";
			default -> "Client authentication is unavailable";
		};
		return new OAuth2AuthenticationException(new OAuth2Error(code, description, null));
	}

}
