package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

class AuthorizationSnapshotMapperTests {

	private static final UUID CLIENT_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a2001");

	private static final UUID USER_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a2002");

	private static final UUID SESSION_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a2003");

	private static final Instant ISSUED_AT = Instant.parse("2026-07-16T10:00:00Z");

	private static final String CODE_CHALLENGE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

	private final AuthorizationSnapshotMapper mapper = new AuthorizationSnapshotMapper(new AuthorizationJsonCodec());

	@Test
	void mapsTheSupportedOfficialAggregate() {
		Map<String, Object> accessClaims = Map.of("sub", USER_ID.toString(), "iat", ISSUED_AT);
		Map<String, Object> idClaims = Map.of("sub", USER_ID.toString(), "iat", ISSUED_AT,
				"exp", ISSUED_AT.plusSeconds(600));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				ISSUED_AT, ISSUED_AT.plusSeconds(600), Set.of("openid"));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", ISSUED_AT,
				ISSUED_AT.plusSeconds(3600));
		OidcIdToken idToken = new OidcIdToken("id-token", ISSUED_AT, ISSUED_AT.plusSeconds(600), idClaims);
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("authorization-code", ISSUED_AT.minusSeconds(30),
				ISSUED_AT.plusSeconds(300));
		OAuth2Authorization authorization = baseAuthorization(authorizationRequest())
			.authorizedScopes(Set.of("openid"))
			.token(code)
			.token(accessToken, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, accessClaims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.refreshToken(refreshToken)
			.token(idToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idClaims))
			.invalidate(code)
			.build();

		AuthorizationSnapshot snapshot = this.mapper.toSnapshot(authorization);

		assertThat(snapshot.clientId()).isEqualTo(CLIENT_ID);
		assertThat(snapshot.requestParameters()).containsEntry("code_challenge", CODE_CHALLENGE);
		assertThat(snapshot.tokens()).containsOnlyKeys(AuthorizationTokenKind.AUTHORIZATION_CODE,
				AuthorizationTokenKind.ACCESS_TOKEN, AuthorizationTokenKind.REFRESH_TOKEN,
				AuthorizationTokenKind.ID_TOKEN);
		assertThat(snapshot.tokens().get(AuthorizationTokenKind.ACCESS_TOKEN).claims()).isEqualTo(accessClaims);
		assertThat(snapshot.toString()).doesNotContain("access-token", "authorization-code", "client-state");
	}

	@Test
	void mapsTheOfficialClientCredentialsAggregate() {
		OAuth2Authorization authorization = clientCredentialsAuthorization(Set.of("scim.read"), Set.of("scim.read"));

		AuthorizationSnapshot snapshot = this.mapper.toSnapshot(authorization, TenantId.DEFAULT.value());

		assertThat(snapshot.tenantId()).isEqualTo(TenantId.DEFAULT.value());
		assertThat(snapshot.clientId()).isEqualTo(CLIENT_ID);
		assertThat(snapshot.clientIdentifier()).isEqualTo("mapper-service-client");
		assertThat(snapshot.grantType()).isEqualTo(AuthorizationGrantKind.CLIENT_CREDENTIALS);
		assertThat(snapshot.principal()).isNull();
		assertThat(snapshot.principalAuthorities()).isEmpty();
		assertThat(snapshot.authorizationUri()).isNull();
		assertThat(snapshot.requestParameters()).isEmpty();
		assertThat(snapshot.requestedScopes()).containsExactly("scim.read");
		assertThat(snapshot.authorizedScopes()).containsExactly("scim.read");
		assertThat(snapshot.tokens()).containsOnlyKeys(AuthorizationTokenKind.ACCESS_TOKEN);
		assertThat(snapshot.tokens().get(AuthorizationTokenKind.ACCESS_TOKEN).claims())
			.containsEntry("sub", "mapper-service-client");
		assertThat(snapshot.toString()).doesNotContain("service-access-token", "tenant_id");
		assertThat(snapshot.tokens().get(AuthorizationTokenKind.ACCESS_TOKEN).toString())
			.doesNotContain("service-access-token", "mapper-service-client");
	}

	@Test
	void rejectsUnknownAuthorizationAndRequestState() {
		OAuth2Authorization unknownAttribute = baseAuthorization(authorizationRequest())
			.attribute("unknown", "value")
			.build();
		OAuth2AuthorizationRequest requestWithAttribute = OAuth2AuthorizationRequest.from(authorizationRequest())
			.attributes(attributes -> attributes.put("unknown", "value"))
			.build();
		OAuth2Authorization unknownRequestAttribute = baseAuthorization(requestWithAttribute).build();
		OAuth2AuthorizationRequest requestWithParameter = OAuth2AuthorizationRequest.from(authorizationRequest())
			.additionalParameters(parameters -> parameters.put("audience", "api"))
			.build();
		OAuth2Authorization unknownRequestParameter = baseAuthorization(requestWithParameter).build();

		assertThatThrownBy(() -> this.mapper.toSnapshot(unknownAttribute))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization contains unsupported attributes");
		assertThatThrownBy(() -> this.mapper.toSnapshot(unknownRequestAttribute))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization request attributes are not supported");
		assertThatThrownBy(() -> this.mapper.toSnapshot(unknownRequestParameter))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization request contains unsupported additional parameters");
	}

	@Test
	void rejectsArbitraryPrincipalsAndUnsupportedTokenState() {
		UsernamePasswordAuthenticationToken arbitraryPrincipal = UsernamePasswordAuthenticationToken.authenticated(
				USER_ID.toString(), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authorization unsupportedPrincipal = baseAuthorization(authorizationRequest())
			.attribute(Principal.class.getName(), arbitraryPrincipal)
			.build();
		AuthorizationPrincipal iamPrincipal = new AuthorizationPrincipal(TenantId.DEFAULT, new UserId(USER_ID),
				new SessionId(SESSION_ID), SessionAuthenticationMethod.PASSWORD, ISSUED_AT.minusSeconds(60));
		AuthorizationUserAuthentication authenticationWithoutFactor = AuthorizationUserAuthentication
			.authenticated(iamPrincipal, List.of(new SimpleGrantedAuthority("ROLE_USER")));
		OAuth2Authorization missingFactor = baseAuthorization(authorizationRequest())
			.attribute(Principal.class.getName(), authenticationWithoutFactor)
			.build();
		OAuth2Authorization refreshToken = baseAuthorization(authorizationRequest())
			.refreshToken(new OAuth2RefreshToken("refresh-token", ISSUED_AT, ISSUED_AT.plusSeconds(600)))
			.build();
		OAuth2Authorization customToken = baseAuthorization(authorizationRequest())
			.token(new UnsupportedToken("custom-token", ISSUED_AT, ISSUED_AT.plusSeconds(600)))
			.build();

		assertThatThrownBy(() -> this.mapper.toSnapshot(unsupportedPrincipal))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization principal must be an authenticated credential-free IAM user");
		assertThatThrownBy(() -> this.mapper.toSnapshot(missingFactor))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization principal authentication factor is required");
		assertThatThrownBy(() -> this.mapper.toSnapshot(refreshToken))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Refresh tokens require an issued access token");
		assertThatThrownBy(() -> this.mapper.toSnapshot(customToken))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization contains unsupported token state");
	}

	@Test
	void rejectsUnknownOrUnsupportedAccessTokenMetadata() {
		Map<String, Object> claims = Map.of("sub", USER_ID.toString(), "iat", ISSUED_AT);
		OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				ISSUED_AT, ISSUED_AT.plusSeconds(600), Set.of("openid"));
		OAuth2Authorization unknownMetadata = baseAuthorization(authorizationRequest())
			.authorizedScopes(Set.of("openid"))
			.token(token, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
				metadata.put("unknown", "value");
			})
			.build();
		OAuth2Authorization referenceToken = baseAuthorization(authorizationRequest())
			.authorizedScopes(Set.of("openid"))
			.token(token, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.REFERENCE.getValue());
			})
			.build();

		assertThatThrownBy(() -> this.mapper.toSnapshot(unknownMetadata))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization token contains unsupported metadata");
		assertThatThrownBy(() -> this.mapper.toSnapshot(referenceToken))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Only self-contained access tokens are supported");
	}

	@Test
	void rejectsInvalidTokenStateTransitionsAndScopes() {
		Map<String, Object> claims = Map.of("sub", USER_ID.toString(), "iat", ISSUED_AT);
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("authorization-code", ISSUED_AT.minusSeconds(30),
				ISSUED_AT.plusSeconds(300));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				ISSUED_AT, ISSUED_AT.plusSeconds(600), Set.of("openid"));
		OAuth2Authorization activeCode = baseAuthorization(authorizationRequest())
			.authorizedScopes(Set.of("openid"))
			.token(code)
			.token(accessToken, metadata -> officialAccessTokenMetadata(metadata, claims))
			.build();
		OAuth2AccessToken overScopedToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"over-scoped-token", ISSUED_AT, ISSUED_AT.plusSeconds(600), Set.of("openid", "admin"));
		OAuth2Authorization overScoped = baseAuthorization(authorizationRequest())
			.authorizedScopes(Set.of("openid"))
			.token(code)
			.token(overScopedToken, metadata -> officialAccessTokenMetadata(metadata, claims))
			.invalidate(code)
			.build();

		assertThatThrownBy(() -> this.mapper.toSnapshot(activeCode))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Issued access tokens require an invalidated authorization code");
		assertThatThrownBy(() -> this.mapper.toSnapshot(overScoped))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Access token scopes must be a subset of the authorized scopes");
	}

	@Test
	void rejectsInvalidClientCredentialsAggregateState() {
		OAuth2Authorization valid = clientCredentialsAuthorization(Set.of("scim.read"), Set.of("scim.read"));
		OAuth2Authorization unscoped = clientCredentialsAuthorization(Set.of(), Set.of());
		OAuth2Authorization unsupportedAttribute = OAuth2Authorization.from(valid)
			.attribute(Principal.class.getName(), "unexpected")
			.build();
		OAuth2Authorization mismatchedScopes = clientCredentialsAuthorization(Set.of("scim.read"), Set.of("scim.write"));
		OAuth2Authorization withRefreshToken = OAuth2Authorization.from(valid)
			.refreshToken(new OAuth2RefreshToken("refresh-token", ISSUED_AT, ISSUED_AT.plusSeconds(600)))
			.build();

		assertThatThrownBy(() -> this.mapper.toSnapshot(valid))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Client-credentials tenant ID is required");
		assertThatThrownBy(() -> this.mapper.toSnapshot(unsupportedAttribute, TenantId.DEFAULT.value()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Client-credentials authorization contains unsupported attributes");
		assertThat(this.mapper.toSnapshot(unscoped, TenantId.DEFAULT.value()).authorizedScopes()).isEmpty();
		assertThatThrownBy(() -> this.mapper.toSnapshot(mismatchedScopes, TenantId.DEFAULT.value()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Client-credentials authorization must contain one scoped access token");
		assertThatThrownBy(() -> this.mapper.toSnapshot(withRefreshToken, TenantId.DEFAULT.value()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Client-credentials authorization must contain one scoped access token");
	}

	private static OAuth2Authorization clientCredentialsAuthorization(Set<String> authorizedScopes,
			Set<String> tokenScopes) {
		Map<String, Object> claims = Map.of("sub", "mapper-service-client", "iat", ISSUED_AT);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"service-access-token", ISSUED_AT, ISSUED_AT.plusSeconds(300), tokenScopes);
		return OAuth2Authorization.withRegisteredClient(serviceRegisteredClient())
			.id(UUID.randomUUID().toString())
			.principalName("mapper-service-client")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizedScopes(authorizedScopes)
			.token(accessToken, metadata -> officialAccessTokenMetadata(metadata, claims))
			.build();
	}

	private static OAuth2Authorization.Builder baseAuthorization(OAuth2AuthorizationRequest request) {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT, new UserId(USER_ID),
				new SessionId(SESSION_ID), SessionAuthenticationMethod.PASSWORD, ISSUED_AT.minusSeconds(60));
		AuthorizationUserAuthentication authentication = AuthorizationUserAuthentication.authenticated(principal,
				List.of(new SimpleGrantedAuthority("ROLE_USER"), FactorGrantedAuthority
					.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
					.issuedAt(principal.authenticatedAt())
					.build()));
		return OAuth2Authorization.withRegisteredClient(registeredClient())
			.id(UUID.randomUUID().toString())
			.principalName(USER_ID.toString())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.attribute(Principal.class.getName(), authentication)
			.attribute(OAuth2AuthorizationRequest.class.getName(), request);
	}

	private static RegisteredClient registeredClient() {
		return RegisteredClient.withId(CLIENT_ID.toString())
			.clientId("mapper-test-client")
			.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri("https://client.example.test/callback")
			.scope("openid")
			.build();
	}

	private static RegisteredClient serviceRegisteredClient() {
		return RegisteredClient.withId(CLIENT_ID.toString())
			.clientId("mapper-service-client")
			.clientAuthenticationMethod(
					org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.scope("scim.read")
			.scope("scim.write")
			.build();
	}

	private static OAuth2AuthorizationRequest authorizationRequest() {
		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://issuer.example.test/oauth2/authorize")
			.clientId("mapper-test-client")
			.redirectUri("https://client.example.test/callback")
			.scopes(Set.of("openid"))
			.state("client-state")
			.additionalParameters(Map.of("code_challenge", CODE_CHALLENGE,
					"code_challenge_method", "S256", "nonce", "oidc-nonce"))
			.build();
	}

	private static void officialAccessTokenMetadata(Map<String, Object> metadata, Map<String, Object> claims) {
		metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
		metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
	}

	private record UnsupportedToken(String tokenValue, Instant issuedAt, Instant expiresAt) implements OAuth2Token {

		@Override
		public String getTokenValue() {
			return this.tokenValue;
		}

		@Override
		public Instant getIssuedAt() {
			return this.issuedAt;
		}

		@Override
		public Instant getExpiresAt() {
			return this.expiresAt;
		}

	}

}
