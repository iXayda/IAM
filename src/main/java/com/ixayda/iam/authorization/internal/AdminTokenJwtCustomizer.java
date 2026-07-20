package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AdminMfaPolicy;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.client.OAuthClientSettings;
import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

final class AdminTokenJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private static final OAuth2Error MFA_REQUIRED = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
			"Recent multi-factor authentication is required for iam.admin.", null);

	private final String audience;

	private final AllRequiredFactorsAuthorizationManager<JwtEncodingContext> mfa;

	AdminTokenJwtCustomizer(URI audience, AdminMfaPolicy policy) {
		this(audience, policy, Clock.systemUTC());
	}

	AdminTokenJwtCustomizer(URI audience, AdminMfaPolicy policy, Clock clock) {
		this.audience = Objects.requireNonNull(audience, "Admin token audience must not be null").toASCIIString();
		this.mfa = Objects.requireNonNull(policy, "Admin MFA policy must not be null").authorizationManager();
		this.mfa.setClock(Objects.requireNonNull(clock, "Admin MFA clock must not be null"));
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
		if (!this.mfa.authorize(() -> authentication, context).isGranted()) {
			throw new OAuth2AuthenticationException(MFA_REQUIRED);
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
