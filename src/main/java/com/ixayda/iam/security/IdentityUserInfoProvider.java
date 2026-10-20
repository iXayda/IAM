package com.ixayda.iam.security;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.service.IdentityUsers;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

/** Current UserInfo claims are projected under the verified access token's subject and grant locks. */
final class IdentityUserInfoProvider implements AuthenticationProvider {

	private final IdentityAccessTokenVerifier verifier;
	private final IdentityUsers users;

	IdentityUserInfoProvider(IdentityAccessTokenVerifier verifier, IdentityUsers users) { this.verifier = verifier; this.users = users; }

	@Override
	public Authentication authenticate(Authentication authentication) {
		if (!(authentication instanceof OidcUserInfoAuthenticationToken request)) { return null; }
		if (!(request.getPrincipal() instanceof BearerTokenAuthenticationToken bearer)) { throw new DeniedException("invalid_token", null); }
		try {
			return this.verifier.use(bearer.getToken(), token -> {
				UUID subject = token.access().userId();
				if (!token.scopes().contains("openid")) { throw new DeniedException("insufficient_scope", subject); }
				var claims = new HashMap<String, Object>(); claims.put("sub", subject.toString());
				if (token.scopes().contains("profile")) {
					var user = this.users.findById(subject).orElseThrow(() -> new IllegalStateException("Validated subject is missing"));
					claims.put("name", user.displayName()); claims.put("preferred_username", user.username());
				}
				var principal = UsernamePasswordAuthenticationToken.authenticated(subject.toString(), null, List.of());
				return new OidcUserInfoAuthenticationToken(principal, new OidcUserInfo(claims));
			}).orElseThrow(() -> new DeniedException("invalid_token", null));
		}
		catch (OAuth2AuthenticationException ex) { throw ex; }
		catch (RuntimeException ex) { throw new DeniedException("server_error", null); }
	}

	@Override
	public boolean supports(Class<?> authentication) { return OidcUserInfoAuthenticationToken.class.isAssignableFrom(authentication); }

	static final class DeniedException extends OAuth2AuthenticationException {
		private final UUID subject;
		DeniedException(String code, UUID subject) { super(code); this.subject = subject; }
		UUID subject() { return this.subject; }
	}

}
