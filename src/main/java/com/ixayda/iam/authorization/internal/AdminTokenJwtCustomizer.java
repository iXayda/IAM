package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.client.OAuthClientSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

final class AdminTokenJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final String audience;

	AdminTokenJwtCustomizer(URI audience) {
		this.audience = Objects.requireNonNull(audience, "Admin token audience must not be null").toASCIIString();
	}

	@Override
	public void customize(JwtEncodingContext context) {
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
				|| !context.getAuthorizedScopes().contains(AdminAccessTokenClaims.SCOPE)
				|| !isUserGrant(context.getAuthorizationGrantType())) {
			return;
		}
		if (!(context.getPrincipal() instanceof AuthorizationUserAuthentication authentication)) {
			throw new IllegalStateException("Admin access token principal is invalid");
		}
		AuthorizationPrincipal principal = authentication.getPrincipal();
		Object tenantSetting = context.getRegisteredClient()
			.getClientSettings()
			.getSetting(OAuthClientSettings.TENANT_ID);
		if (!(tenantSetting instanceof String tenantId) || !principal.tenantId().toString().equals(tenantId)) {
			throw new IllegalStateException("Admin access token tenant is invalid");
		}
		context.getClaims()
			.subject(principal.userId().toString())
			.audience(List.of(this.audience))
			.claim(AdminAccessTokenClaims.TENANT_ID, tenantId)
			.claim(AdminAccessTokenClaims.USER_ID, principal.userId().toString())
			.claim(AdminAccessTokenClaims.SESSION_ID, principal.sessionId().toString())
			.claim(AdminAccessTokenClaims.AUTHENTICATION_METHOD,
					principal.authenticationMethod().name().toLowerCase(Locale.ROOT))
			.claim(AdminAccessTokenClaims.AUTHENTICATION_TIME, principal.authenticatedAt().getEpochSecond());
	}

	private static boolean isUserGrant(AuthorizationGrantType grantType) {
		return AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)
				|| AuthorizationGrantType.REFRESH_TOKEN.equals(grantType);
	}

}
