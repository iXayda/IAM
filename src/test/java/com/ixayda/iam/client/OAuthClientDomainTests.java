package com.ixayda.iam.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class OAuthClientDomainTests {

	private static final ClientId CLIENT_ID =
			new ClientId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc3"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final ClientSecretMetadata SECRET_METADATA =
			new ClientSecretMetadata(CREATED_AT, CREATED_AT.plus(Duration.ofDays(90)));

	private static final ClientRedirectUri REDIRECT_URI =
			new ClientRedirectUri("https://client.example.test/callback");

	private static final ClientScope OPENID = new ClientScope("openid");

	@Test
	void usesUuidBackedInternalIdsAndOpaqueProtocolIdentifiers() {
		assertThat(ClientId.from(CLIENT_ID.toString())).isEqualTo(CLIENT_ID);
		assertThat(ClientId.random().value()).isNotNull();
		assertThat(new ClientIdentifier("web-app_01.example").toString()).isEqualTo("web-app_01.example");
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", " client", "client ", "client id", "client/id", "client:id", "-client" })
	void rejectsInvalidProtocolClientIdentifiers(String value) {
		assertThatThrownBy(() -> new ClientIdentifier(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsProtocolClientIdentifiersOverOneHundredTwentyEightCharacters() {
		assertThatThrownBy(() -> new ClientIdentifier("a".repeat(129)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void acceptsProtocolClientIdentifiersAtTheMaximumLength() {
		assertThat(new ClientIdentifier("a".repeat(128)).value()).hasSize(128);
	}

	@Test
	void validatesExactHttpsRedirectUris() {
		assertThat(new ClientRedirectUri("https://client.example.test/callback?channel=web").toString())
			.isEqualTo("https://client.example.test/callback?channel=web");
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", " callback", "/callback", "http://client.example.test/callback",
			"http://127.0.0.1:49152/callback", "http://[::1]:49152/callback",
			"http://localhost/callback", "https://user@client.example.test/callback",
			"https://client.example.test/callback#fragment", "https://*.example.test/callback",
			"https://client.example.test/回调",
			"https://client.example.test/a/../callback", "https://client.example.test:0/callback",
			"https://client.example.test:65536/callback", "https://client.example.test:/callback" })
	void rejectsUnsafeRedirectUris(String value) {
		assertThatThrownBy(() -> new ClientRedirectUri(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsRedirectUrisOverTwoThousandFortyEightCharacters() {
		assertThatThrownBy(() -> new ClientRedirectUri("https://client.example.test/" + "a".repeat(2049)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "read write", "quoted\"scope", "path\\scope" })
	void rejectsInvalidScopes(String value) {
		assertThatThrownBy(() -> new ClientScope(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void createsTenantOwnedPublicClientsWithSecureProtocolDefaults() {
		Set<ClientRedirectUri> redirects = new LinkedHashSet<>(Set.of(REDIRECT_URI));
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier("web-app"), "  Web App  ",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, redirects,
				Set.of(new ClientRedirectUri("https://client.example.test/signed-out")),
				Set.of(OPENID, new ClientScope("api.read")), ClientTokenPolicy.secureDefaults());

		OAuthClient client = OAuthClient.create(CLIENT_ID, TenantId.DEFAULT, request, null, CREATED_AT);
		redirects.clear();

		assertThat(client.displayName()).isEqualTo("Web App");
		assertThat(client.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(client.status()).isEqualTo(ClientStatus.ACTIVE);
		assertThat(client.version()).isZero();
		assertThat(client.redirectUris()).containsExactly(REDIRECT_URI);
		assertThat(client.hasSecret()).isFalse();
		assertThat(client.requiresProofKey()).isTrue();
		assertThat(client.supportsRefreshTokens()).isFalse();
		assertThat(client.requiresConsent()).isTrue();
	}

	@Test
	void enforcesAuthenticationAndSecretMetadataByClientType() {
		assertThatThrownBy(() -> OAuthClient.create(CLIENT_ID, TenantId.DEFAULT,
				request(ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(OPENID), Set.of()),
				SECRET_METADATA, CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> request(ClientType.PUBLIC, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				Set.of(OPENID), Set.of()))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> request(ClientType.CONFIDENTIAL, ClientAuthenticationMethod.NONE,
				Set.of(OPENID), Set.of()))
			.isInstanceOf(IllegalArgumentException.class);

		OAuthClient confidential = OAuthClient.create(CLIENT_ID, TenantId.DEFAULT,
				request(ClientType.CONFIDENTIAL, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Set.of(OPENID),
						Set.of()),
				SECRET_METADATA, CREATED_AT);
		assertThat(confidential.hasSecret()).isTrue();
		assertThat(confidential.authenticationMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(SECRET_METADATA.isExpiredAt(SECRET_METADATA.expiresAt())).isTrue();
	}

	@Test
	void allowsOnlyConfidentialClientsToEnableRefreshTokensExplicitly() {
		ClientTokenPolicy refreshPolicy = ClientTokenPolicy.refreshEnabledDefaults();
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier("refresh-client"), "Refresh Client",
				ClientType.CONFIDENTIAL, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Set.of(REDIRECT_URI), Set.of(),
				Set.of(OPENID), refreshPolicy);

		OAuthClient client = OAuthClient.create(CLIENT_ID, TenantId.DEFAULT, request, SECRET_METADATA, CREATED_AT);

		assertThat(client.supportsRefreshTokens()).isTrue();
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("public-refresh-client"),
				"Public Refresh Client", ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(REDIRECT_URI), Set.of(),
				Set.of(OPENID), refreshPolicy))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("confidential client");
		assertThatThrownBy(() -> new OAuthClient(CLIENT_ID, TenantId.DEFAULT,
				new ClientIdentifier("stored-public-refresh-client"), "Stored Public Refresh Client", ClientType.PUBLIC,
				ClientAuthenticationMethod.NONE, ClientStatus.ACTIVE, null, Set.of(REDIRECT_URI), Set.of(), Set.of(OPENID),
				refreshPolicy, 0, CREATED_AT, CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("confidential client");
	}

	@Test
	void rejectsInvalidSecretLifetimes() {
		assertThatThrownBy(() -> new ClientSecretMetadata(CREATED_AT, CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void requiresOpenIdScopeForPostLogoutRedirects() {
		ClientRedirectUri logoutUri = new ClientRedirectUri("https://client.example.test/signed-out");

		assertThatThrownBy(() -> request(ClientType.PUBLIC, ClientAuthenticationMethod.NONE,
				Set.of(new ClientScope("api.read")),
				Set.of(logoutUri))).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void rejectsOfflineAccessScope() {
		assertThatThrownBy(() -> request(ClientType.PUBLIC, ClientAuthenticationMethod.NONE,
				Set.of(OPENID, new ClientScope("offline_access")), Set.of()))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void requiresExplicitNonEmptyRedirectsScopesAndTokenPolicy() {
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("web-app"), "Web App",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(), Set.of(), Set.of(OPENID),
				ClientTokenPolicy.secureDefaults())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("web-app"), "Web App",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(REDIRECT_URI), Set.of(), Set.of(),
				ClientTokenPolicy.secureDefaults())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("web-app"), "Web App",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(REDIRECT_URI), Set.of(), Set.of(OPENID), null))
			.isInstanceOf(NullPointerException.class);
	}

	@Test
	void boundsRegistrationCollectionSizes() {
		Set<ClientRedirectUri> redirects = new HashSet<>();
		for (int index = 0; index <= 20; index++) {
			redirects.add(new ClientRedirectUri("https://client" + index + ".example.test/callback"));
		}
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("web-app"), "Web App",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, redirects, Set.of(), Set.of(OPENID),
				ClientTokenPolicy.secureDefaults())).isInstanceOf(IllegalArgumentException.class);

		Set<ClientScope> scopes = new HashSet<>();
		for (int index = 0; index <= 50; index++) {
			scopes.add(new ClientScope("api.scope." + index));
		}
		assertThatThrownBy(() -> new CreateClientRequest(new ClientIdentifier("web-app"), "Web App",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(REDIRECT_URI), Set.of(), scopes,
				ClientTokenPolicy.secureDefaults())).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void boundsTokenLifetimesAndUsesSecureRefreshDefaults() {
		assertThat(ClientTokenPolicy.secureDefaults().authorizationCodeTtl()).isEqualTo(Duration.ofMinutes(5));
		assertThat(ClientTokenPolicy.secureDefaults().accessTokenTtl()).isEqualTo(Duration.ofMinutes(5));
		assertThat(ClientTokenPolicy.secureDefaults().refreshTokensEnabled()).isFalse();
		assertThat(ClientTokenPolicy.secureDefaults().refreshTokenTtl()).isEqualTo(Duration.ofHours(1));
		assertThat(ClientTokenPolicy.refreshEnabledDefaults().refreshTokensEnabled()).isTrue();
		assertThat(ClientTokenPolicy.refreshEnabledDefaults().refreshTokenTtl()).isEqualTo(Duration.ofHours(1));
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ZERO, Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofSeconds(29), Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(11), Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(61)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMillis(30_500), Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("whole number of seconds");
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true, null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true,
				Duration.ofMillis(300_500)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("whole number of seconds");
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true,
				Duration.ofSeconds(299)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true,
				Duration.ofDays(30).plusSeconds(1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true,
				Duration.ofMinutes(5)))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("longer than the access token TTL");
		assertThat(new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(1), true, Duration.ofMinutes(5))
			.refreshTokenTtl()).isEqualTo(Duration.ofMinutes(5));
		assertThat(new ClientTokenPolicy(Duration.ofMinutes(5), Duration.ofMinutes(5), true, Duration.ofDays(30))
			.refreshTokenTtl()).isEqualTo(Duration.ofDays(30));
	}

	@Test
	void changesStatusIdempotentlyWithoutChangingTenantOwnership() {
		OAuthClient active = OAuthClient.create(CLIENT_ID, TenantId.DEFAULT,
				request(ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(OPENID), Set.of()), null,
				CREATED_AT);
		Instant disabledAt = CREATED_AT.plusSeconds(60);

		assertThat(active.activate(disabledAt)).isSameAs(active);
		OAuthClient disabled = active.disable(disabledAt);
		assertThat(disabled.status()).isEqualTo(ClientStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(disabled.updatedAt()).isEqualTo(disabledAt);
		assertThat(disabled.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(disabled.disable(disabledAt.plusSeconds(1))).isSameAs(disabled);
		assertThat(disabled.activate(disabledAt.plusSeconds(2)).status()).isEqualTo(ClientStatus.ACTIVE);
	}

	@Test
	void rejectsInvalidAggregateStateAndBackwardStatusChanges() {
		CreateClientRequest request = request(ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(OPENID),
				Set.of());

		assertThatThrownBy(() -> new OAuthClient(CLIENT_ID, TenantId.DEFAULT, request.identifier(),
				request.displayName(), request.type(), request.authenticationMethod(), ClientStatus.ACTIVE, null,
				request.redirectUris(), request.postLogoutRedirectUris(), request.scopes(), request.tokenPolicy(), -1,
				CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> OAuthClient.create(CLIENT_ID, TenantId.DEFAULT, request, null, CREATED_AT)
			.disable(CREATED_AT.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
	}

	private CreateClientRequest request(ClientType type, ClientAuthenticationMethod authenticationMethod,
			Set<ClientScope> scopes,
			Set<ClientRedirectUri> postLogoutRedirectUris) {
		return new CreateClientRequest(new ClientIdentifier("web-app"), "Web App", type, authenticationMethod,
				Set.of(REDIRECT_URI), postLogoutRedirectUris, scopes, ClientTokenPolicy.secureDefaults());
	}

}
