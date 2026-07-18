package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.ixayda.iam.client.OAuthClientSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

final class ServiceTokenJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	static final String TENANT_ID_CLAIM = "tenant_id";

	static final String CLIENT_ID_CLAIM = "client_id";

	private final String audience;

	ServiceTokenJwtCustomizer(URI audience) {
		this.audience = Objects.requireNonNull(audience, "Service token audience must not be null").toASCIIString();
	}

	@Override
	public void customize(JwtEncodingContext context) {
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
				|| !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
			return;
		}
		Object setting = context.getRegisteredClient().getClientSettings().getSetting(OAuthClientSettings.TENANT_ID);
		if (!(setting instanceof String value)) {
			throw new IllegalStateException("Service client tenant setting is missing");
		}
		String tenantId;
		try {
			tenantId = UUID.fromString(value).toString();
		}
		catch (IllegalArgumentException exception) {
			throw new IllegalStateException("Service client tenant setting is invalid", exception);
		}
		String clientId = context.getRegisteredClient().getClientId();
		context.getClaims()
			.subject(clientId)
			.audience(List.of(this.audience))
			.claim(CLIENT_ID_CLAIM, clientId)
			.claim(TENANT_ID_CLAIM, tenantId);
	}

}
