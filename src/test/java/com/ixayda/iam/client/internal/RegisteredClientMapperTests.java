package com.ixayda.iam.client.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.ClientSecretMetadata;
import com.ixayda.iam.client.ClientStatus;
import com.ixayda.iam.client.ClientTokenPolicy;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

class RegisteredClientMapperTests {

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final ClientRedirectUri REDIRECT_URI =
			new ClientRedirectUri("https://client.example.test/callback");

	private final RegisteredClientMapper mapper = new RegisteredClientMapper();

	@Test
	void mapsAConfidentialClientToTheExplicitAuthorizationServerContract() {
		ClientSecretMetadata secretMetadata =
				new ClientSecretMetadata(CREATED_AT, CREATED_AT.plus(Duration.ofDays(90)));
		OAuthClient client = client(ClientType.CONFIDENTIAL, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				secretMetadata);
		String encodedSecret = "{bcrypt}" + "a".repeat(60);

		RegisteredClient registeredClient =
				this.mapper.toRegisteredClient(new StoredOAuthClient(client, encodedSecret));

		assertThat(registeredClient.getId()).isEqualTo(client.id().toString());
		assertThat(registeredClient.getClientId()).isEqualTo(client.identifier().value());
		assertThat(registeredClient.getClientIdIssuedAt()).isEqualTo(CREATED_AT);
		assertThat(registeredClient.getClientSecret()).isEqualTo(encodedSecret);
		assertThat(registeredClient.getClientSecretExpiresAt()).isEqualTo(secretMetadata.expiresAt());
		assertThat(registeredClient.getClientAuthenticationMethods())
			.containsExactly(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(registeredClient.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(registeredClient.getRedirectUris()).containsExactly(REDIRECT_URI.value());
		assertThat(registeredClient.getPostLogoutRedirectUris())
			.containsExactly("https://client.example.test/logout");
		assertThat(registeredClient.getScopes()).containsExactlyInAnyOrder("openid", "api.read");
		assertThat(registeredClient.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClient.getClientSettings().isRequireAuthorizationConsent()).isTrue();
		String tenantId = registeredClient.getClientSettings().getSetting(RegisteredClientMapper.TENANT_ID_SETTING);
		assertThat(tenantId).isEqualTo(TenantId.DEFAULT.toString());
		assertThat((String) registeredClient.getClientSettings()
			.getSetting(RegisteredClientMapper.SECRET_ENCODING_FINGERPRINT_SETTING))
			.hasSize(64)
			.isNotEqualTo(encodedSecret);
		assertThat(registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive())
			.isEqualTo(Duration.ofMinutes(4));
		assertThat(registeredClient.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(7));
		assertThat(registeredClient.getTokenSettings().getAccessTokenFormat())
			.isEqualTo(OAuth2TokenFormat.SELF_CONTAINED);
		assertThat(registeredClient.getTokenSettings().isReuseRefreshTokens()).isFalse();
		assertThat(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm())
			.isEqualTo(SignatureAlgorithm.RS256);
		assertThat(registeredClient.toString()).doesNotContain(encodedSecret);
	}

	@Test
	void mapsAPublicClientWithoutASecretOrRefreshGrant() {
		OAuthClient client = client(ClientType.PUBLIC, ClientAuthenticationMethod.NONE, null);

		RegisteredClient registeredClient = this.mapper.toRegisteredClient(new StoredOAuthClient(client, null));

		assertThat(registeredClient.getClientSecret()).isNull();
		assertThat(registeredClient.getClientSecretExpiresAt()).isNull();
		assertThat(registeredClient.getClientAuthenticationMethods())
			.containsExactly(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE);
		assertThat(registeredClient.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE)
			.doesNotContain(AuthorizationGrantType.REFRESH_TOKEN);
	}

	private static OAuthClient client(ClientType type, ClientAuthenticationMethod authenticationMethod,
			ClientSecretMetadata secretMetadata) {
		return new OAuthClient(ClientId.random(), TenantId.DEFAULT, new ClientIdentifier("registered-client"),
				"Registered Client", type, authenticationMethod, ClientStatus.ACTIVE, secretMetadata,
				Set.of(REDIRECT_URI), Set.of(new ClientRedirectUri("https://client.example.test/logout")),
				Set.of(new ClientScope("openid"), new ClientScope("api.read")),
				new ClientTokenPolicy(Duration.ofMinutes(4), Duration.ofMinutes(7)), 0, CREATED_AT, CREATED_AT);
	}

}
