package com.ixayda.iam.client.internal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.client.OAuthClientSettings;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

@Component
class RegisteredClientMapper {

	static final String TENANT_ID_SETTING = OAuthClientSettings.TENANT_ID;

	static final String SECRET_ENCODING_FINGERPRINT_SETTING = "com.ixayda.iam.client-secret-encoding-fingerprint";

	RegisteredClient toRegisteredClient(StoredOAuthClient stored) {
		OAuthClient client = stored.client();
		ClientSettings.Builder clientSettings = ClientSettings.builder()
			.requireProofKey(client.requiresProofKey())
			.requireAuthorizationConsent(client.requiresConsent())
			.setting(TENANT_ID_SETTING, client.tenantId().toString());
		if (stored.encodedSecret() != null) {
			clientSettings.setting(SECRET_ENCODING_FINGERPRINT_SETTING, secretEncodingFingerprint(stored.encodedSecret()));
		}
		RegisteredClient.Builder builder = RegisteredClient.withId(client.id().toString())
			.clientId(client.identifier().value())
			.clientIdIssuedAt(client.createdAt())
			.clientName(client.displayName())
			.clientAuthenticationMethod(authenticationMethod(client))
			.authorizationGrantType(authorizationGrantType(client))
			.clientSettings(clientSettings.build())
			.tokenSettings(TokenSettings.builder()
				.authorizationCodeTimeToLive(client.tokenPolicy().authorizationCodeTtl())
				.accessTokenTimeToLive(client.tokenPolicy().accessTokenTtl())
				.refreshTokenTimeToLive(client.tokenPolicy().refreshTokenTtl())
				.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
				.reuseRefreshTokens(false)
				.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
				.build());
		if (client.supportsRefreshTokens()) {
			builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
		}

		client.redirectUris().stream().map(ClientRedirectUri::value).forEach(builder::redirectUri);
		client.postLogoutRedirectUris().stream().map(ClientRedirectUri::value)
			.forEach(builder::postLogoutRedirectUri);
		client.scopes().stream().map(ClientScope::value).forEach(builder::scope);
		if (stored.encodedSecret() != null) {
			builder.clientSecret(stored.encodedSecret())
				.clientSecretExpiresAt(client.secretMetadata().expiresAt());
		}
		return builder.build();
	}

	static String secretEncodingFingerprint(String encodedSecret) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
				.digest(encodedSecret.getBytes(StandardCharsets.US_ASCII));
			return HexFormat.of().formatHex(digest);
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException("SHA-256 is unavailable", ex);
		}
	}

	private static org.springframework.security.oauth2.core.ClientAuthenticationMethod authenticationMethod(
			OAuthClient client) {
		return switch (client.authenticationMethod()) {
			case NONE -> org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
			case CLIENT_SECRET_BASIC ->
				org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		};
	}

	private static AuthorizationGrantType authorizationGrantType(OAuthClient client) {
		return switch (client.authorizationGrant()) {
			case AUTHORIZATION_CODE -> AuthorizationGrantType.AUTHORIZATION_CODE;
			case CLIENT_CREDENTIALS -> AuthorizationGrantType.CLIENT_CREDENTIALS;
		};
	}

}
