package com.ixayda.iam.authorization.internal;

import java.security.Principal;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

final class AuthorizationSnapshotMapper {

	static final String REVISION_ATTRIBUTE = "com.ixayda.iam.authorization.revision";

	private static final Set<String> ALLOWED_ATTRIBUTES = Set.of(Principal.class.getName(),
			OAuth2AuthorizationRequest.class.getName(), OAuth2ParameterNames.STATE, REVISION_ATTRIBUTE);

	private static final Set<String> ALLOWED_SERVICE_ATTRIBUTES = Set.of(REVISION_ATTRIBUTE);

	private static final Set<String> ALLOWED_REQUEST_PARAMETERS =
			Set.of("code_challenge", "code_challenge_method", "nonce", "prompt");

	private static final Pattern CODE_CHALLENGE = Pattern.compile("[A-Za-z0-9_-]{43}");

	private static final int MAXIMUM_TOKEN_VALUE_LENGTH = 24_576;

	private final AuthorizationJsonCodec jsonCodec;

	AuthorizationSnapshotMapper(AuthorizationJsonCodec jsonCodec) {
		this.jsonCodec = Objects.requireNonNull(jsonCodec, "Authorization JSON codec must not be null");
	}

	AuthorizationSnapshot toSnapshot(OAuth2Authorization authorization) {
		return toSnapshot(authorization, null);
	}

	AuthorizationSnapshot toSnapshot(OAuth2Authorization authorization, UUID clientCredentialsTenantId) {
		Objects.requireNonNull(authorization, "Authorization must not be null");
		UUID authorizationId = parseUuid(authorization.getId(), "Authorization ID");
		UUID clientId = parseUuid(authorization.getRegisteredClientId(), "Registered client ID");
		AuthorizationGrantKind grantType = AuthorizationGrantKind.from(authorization.getAuthorizationGrantType());
		return switch (grantType) {
			case AUTHORIZATION_CODE -> authorizationCodeSnapshot(authorization, authorizationId, clientId);
			case CLIENT_CREDENTIALS -> clientCredentialsSnapshot(authorization, authorizationId, clientId,
					clientCredentialsTenantId);
		};
	}

	private AuthorizationSnapshot authorizationCodeSnapshot(OAuth2Authorization authorization, UUID authorizationId,
			UUID clientId) {
		if (!ALLOWED_ATTRIBUTES.containsAll(authorization.getAttributes().keySet())) {
			throw new IllegalArgumentException("Authorization contains unsupported attributes");
		}

		AuthorizationUserAuthentication authentication = principal(authorization);
		AuthorizationPrincipal principal = authentication.getPrincipal();
		if (!principal.getName().equals(authorization.getPrincipalName())) {
			throw new IllegalArgumentException("Authorization principal name must be the stable user ID");
		}
		OAuth2AuthorizationRequest request = authorizationRequest(authorization);
		if (!request.getAttributes().isEmpty()) {
			throw new IllegalArgumentException("Authorization request attributes are not supported");
		}
		if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(request.getGrantType())
				|| !OAuth2AuthorizationResponseType.CODE.equals(request.getResponseType())) {
			throw new IllegalArgumentException("Only authorization code requests are supported");
		}
		Map<String, Object> requestParameters = requestParameters(request.getAdditionalParameters());
		if (!authorization.getAuthorizedScopes().isEmpty()
				&& !request.getScopes().containsAll(authorization.getAuthorizedScopes())) {
			throw new IllegalArgumentException("Authorized scopes must be a subset of requested scopes");
		}

		String consentState = optionalString(authorization.getAttribute(OAuth2ParameterNames.STATE),
				"Authorization consent state");
		Long revision = revision(authorization.getAttribute(REVISION_ATTRIBUTE));
		Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens = tokens(authorization);
		validateProtocolState(consentState, authorization.getAuthorizedScopes(), tokens);
		AuthorizationPrincipal persistedPrincipal = new AuthorizationPrincipal(principal.tenantId(), principal.userId(),
				principal.sessionId(), principal.authenticationMethod(),
				AuthorizationTime.toDatabasePrecision(principal.authenticatedAt()));
		AuthorizationSnapshot snapshot = new AuthorizationSnapshot(authorizationId, principal.tenantId().value(),
				clientId, request.getClientId(), AuthorizationGrantKind.AUTHORIZATION_CODE, persistedPrincipal,
				authorities(authentication, principal),
				request.getAuthorizationUri(), request.getRedirectUri(), request.getState(), requestParameters, request.getScopes(),
				authorization.getAuthorizedScopes(), consentState, revision, tokens);

		this.jsonCodec.write(snapshot.requestParameters());
		snapshot.tokens().values().stream().map(AuthorizationTokenSnapshot::claims).filter(Objects::nonNull)
				.forEach(this.jsonCodec::write);
		if (!sanitizedAuthorizationCode(authorization, snapshot, authentication, request).equals(authorization)) {
			throw new IllegalArgumentException("Authorization contains unsupported token state");
		}
		return snapshot;
	}

	private AuthorizationSnapshot clientCredentialsSnapshot(OAuth2Authorization authorization, UUID authorizationId,
			UUID clientId, UUID tenantId) {
		if (!ALLOWED_SERVICE_ATTRIBUTES.containsAll(authorization.getAttributes().keySet())) {
			throw new IllegalArgumentException("Client-credentials authorization contains unsupported attributes");
		}
		if (tenantId == null) {
			throw new IllegalArgumentException("Client-credentials tenant ID is required");
		}
		String clientIdentifier = authorization.getPrincipalName();
		if (clientIdentifier == null || clientIdentifier.isEmpty()) {
			throw new IllegalArgumentException("Client-credentials principal name must be the client identifier");
		}
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens = tokens(authorization);
		if (!tokens.keySet().equals(Set.of(AuthorizationTokenKind.ACCESS_TOKEN))
				|| !tokens.get(AuthorizationTokenKind.ACCESS_TOKEN).scopes().equals(authorizedScopes)) {
			throw new IllegalArgumentException("Client-credentials authorization must contain one scoped access token");
		}
		Long revision = revision(authorization.getAttribute(REVISION_ATTRIBUTE));
		AuthorizationSnapshot snapshot = new AuthorizationSnapshot(authorizationId, tenantId, clientId, clientIdentifier,
				AuthorizationGrantKind.CLIENT_CREDENTIALS, null, Set.of(), null, null, null, Map.of(), authorizedScopes,
				authorizedScopes, null, revision, tokens);
		snapshot.tokens().values().stream().map(AuthorizationTokenSnapshot::claims).filter(Objects::nonNull)
			.forEach(this.jsonCodec::write);
		if (!sanitizedClientCredentialsAuthorization(authorization, snapshot).equals(authorization)) {
			throw new IllegalArgumentException("Client-credentials authorization contains unsupported token state");
		}
		return snapshot;
	}

	String encodeRequestParameters(Map<String, Object> parameters) {
		return this.jsonCodec.write(parameters);
	}

	String encodeClaims(Map<String, Object> claims) {
		return this.jsonCodec.write(claims);
	}

	Map<String, Object> decodeJson(String json) {
		return this.jsonCodec.read(json);
	}

	private static AuthorizationUserAuthentication principal(OAuth2Authorization authorization) {
		Object value = authorization.getAttribute(Principal.class.getName());
		if (!(value instanceof AuthorizationUserAuthentication authentication) || !authentication.isAuthenticated()
				|| authentication.getCredentials() != null || authentication.getDetails() != null) {
			throw new IllegalArgumentException(
					"Authorization principal must be an authenticated credential-free IAM user");
		}
		return authentication;
	}

	private static OAuth2AuthorizationRequest authorizationRequest(OAuth2Authorization authorization) {
		Object value = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (value == null || value.getClass() != OAuth2AuthorizationRequest.class) {
			throw new IllegalArgumentException("A standard OAuth2AuthorizationRequest is required");
		}
		return (OAuth2AuthorizationRequest) value;
	}

	private static Map<String, Object> requestParameters(Map<String, Object> parameters) {
		if (!ALLOWED_REQUEST_PARAMETERS.containsAll(parameters.keySet())) {
			throw new IllegalArgumentException("Authorization request contains unsupported additional parameters");
		}
		Map<String, Object> validated = new LinkedHashMap<>();
		parameters.forEach((name, value) -> {
			if (!(value instanceof String text) || text.isEmpty()) {
				throw new IllegalArgumentException("Authorization request parameters must be non-empty strings");
			}
			validated.put(name, text);
		});
		Object challenge = validated.get("code_challenge");
		if (!(challenge instanceof String text) || !CODE_CHALLENGE.matcher(text).matches()) {
			throw new IllegalArgumentException("A valid S256 PKCE code challenge is required");
		}
		if (!"S256".equals(validated.get("code_challenge_method"))) {
			throw new IllegalArgumentException("Only the S256 PKCE code challenge method is supported");
		}
		return Collections.unmodifiableMap(validated);
	}

	private static Set<AuthorizationAuthoritySnapshot> authorities(AuthorizationUserAuthentication authentication,
			AuthorizationPrincipal principal) {
		Map<String, AuthorizationAuthoritySnapshot> authorities = new LinkedHashMap<>();
		boolean passwordFactorPresent = false;
		for (GrantedAuthority authority : authentication.getAuthorities()) {
			String value = authority.getAuthority();
			if (value == null || value.isEmpty() || value.length() > 256
					|| !value.chars().allMatch(character -> character >= 33 && character <= 126)) {
				throw new IllegalArgumentException("Authorization principal contains an invalid authority");
			}
			if (authority instanceof FactorGrantedAuthority factor) {
				if (principal.authenticationMethod() != SessionAuthenticationMethod.PASSWORD
						|| (!FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(value)
								&& !FactorGrantedAuthority.OTT_AUTHORITY.equals(value))
						|| factor.getIssuedAt().isAfter(principal.authenticatedAt())) {
					throw new IllegalArgumentException("Authorization principal contains an unsupported factor authority");
				}
				passwordFactorPresent |= FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(value);
			}
			else if (value.startsWith("FACTOR_")) {
				throw new IllegalArgumentException("Authorization principal factor authorities must retain their type");
			}
			Instant issuedAt = authority instanceof FactorGrantedAuthority factor
					? AuthorizationTime.toDatabasePrecision(factor.getIssuedAt()) : null;
			AuthorizationAuthoritySnapshot snapshot = new AuthorizationAuthoritySnapshot(value, issuedAt);
			AuthorizationAuthoritySnapshot existing = authorities.putIfAbsent(value, snapshot);
			if (existing != null && !existing.equals(snapshot)) {
				throw new IllegalArgumentException("Authorization principal contains conflicting authorities");
			}
		}
		if (!passwordFactorPresent) {
			throw new IllegalArgumentException("Authorization principal password factor is required");
		}
		return Collections.unmodifiableSet(new LinkedHashSet<>(authorities.values()));
	}

	private static Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens(
			OAuth2Authorization authorization) {
		if (authorization.getToken(OAuth2DeviceCode.class) != null
				|| authorization.getToken(OAuth2UserCode.class) != null) {
			throw new IllegalArgumentException("Device and user code tokens are not supported");
		}
		Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens =
				new java.util.EnumMap<>(AuthorizationTokenKind.class);
		addCode(tokens, authorization.getToken(OAuth2AuthorizationCode.class));
		addAccessToken(tokens, authorization.getAccessToken());
		addRefreshToken(tokens, authorization.getRefreshToken());
		addIdToken(tokens, authorization.getToken(OidcIdToken.class));
		return tokens;
	}

	private static void validateProtocolState(String consentState, Set<String> authorizedScopes,
			Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens) {
		if (consentState != null && (!authorizedScopes.isEmpty() || !tokens.isEmpty())) {
			throw new IllegalArgumentException("Pending authorization consent state cannot contain issued tokens or scopes");
		}
		AuthorizationTokenSnapshot code = tokens.get(AuthorizationTokenKind.AUTHORIZATION_CODE);
		AuthorizationTokenSnapshot accessToken = tokens.get(AuthorizationTokenKind.ACCESS_TOKEN);
		AuthorizationTokenSnapshot refreshToken = tokens.get(AuthorizationTokenKind.REFRESH_TOKEN);
		AuthorizationTokenSnapshot idToken = tokens.get(AuthorizationTokenKind.ID_TOKEN);
		if (accessToken != null) {
			if (code == null || !code.invalidated()) {
				throw new IllegalArgumentException("Issued access tokens require an invalidated authorization code");
			}
			if (!authorizedScopes.containsAll(accessToken.scopes())) {
				throw new IllegalArgumentException("Access token scopes must be a subset of the authorized scopes");
			}
		}
		if (refreshToken != null && accessToken == null) {
			throw new IllegalArgumentException("Refresh tokens require an issued access token");
		}
		if (idToken != null && (accessToken == null || !authorizedScopes.contains("openid"))) {
			throw new IllegalArgumentException("ID tokens require an OpenID access token authorization");
		}
	}

	private static void addCode(Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens,
			OAuth2Authorization.Token<OAuth2AuthorizationCode> token) {
		if (token == null) {
			return;
		}
		validateMetadata(token, false);
		validateToken(token.getToken().getTokenValue(), token.getToken().getIssuedAt(), token.getToken().getExpiresAt());
		Instant issuedAt = AuthorizationTime.toDatabasePrecision(token.getToken().getIssuedAt());
		Instant expiresAt = AuthorizationTime.toDatabasePrecision(token.getToken().getExpiresAt());
		validateToken(token.getToken().getTokenValue(), issuedAt, expiresAt);
		tokens.put(AuthorizationTokenKind.AUTHORIZATION_CODE,
				new AuthorizationTokenSnapshot(token.getToken().getTokenValue(), issuedAt, expiresAt,
					token.isInvalidated(), null, Set.of(), null));
	}

	private static void addAccessToken(Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens,
			OAuth2Authorization.Token<OAuth2AccessToken> token) {
		if (token == null) {
			return;
		}
		Map<String, Object> claims = validateMetadata(token, true, true);
		OAuth2AccessToken value = token.getToken();
		validateToken(value.getTokenValue(), value.getIssuedAt(), value.getExpiresAt());
		Instant issuedAt = AuthorizationTime.toDatabasePrecision(value.getIssuedAt());
		Instant expiresAt = AuthorizationTime.toDatabasePrecision(value.getExpiresAt());
		validateToken(value.getTokenValue(), issuedAt, expiresAt);
		String tokenType = value.getTokenType().getValue();
		if (!OAuth2AccessToken.TokenType.BEARER.getValue().equals(tokenType)
				&& !OAuth2AccessToken.TokenType.DPOP.getValue().equals(tokenType)) {
			throw new IllegalArgumentException("Unsupported access token type: " + tokenType);
		}
		tokens.put(AuthorizationTokenKind.ACCESS_TOKEN,
				new AuthorizationTokenSnapshot(value.getTokenValue(), issuedAt, expiresAt,
					token.isInvalidated(), tokenType, value.getScopes(), claims));
	}

	private static void addRefreshToken(Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens,
			OAuth2Authorization.Token<OAuth2RefreshToken> token) {
		if (token == null) {
			return;
		}
		validateMetadata(token, false);
		OAuth2RefreshToken value = token.getToken();
		validateToken(value.getTokenValue(), value.getIssuedAt(), value.getExpiresAt());
		Instant issuedAt = AuthorizationTime.toDatabasePrecision(value.getIssuedAt());
		Instant expiresAt = AuthorizationTime.toDatabasePrecision(value.getExpiresAt());
		validateToken(value.getTokenValue(), issuedAt, expiresAt);
		tokens.put(AuthorizationTokenKind.REFRESH_TOKEN,
				new AuthorizationTokenSnapshot(value.getTokenValue(), issuedAt, expiresAt,
					token.isInvalidated(), null, Set.of(), null));
	}

	private static void addIdToken(Map<AuthorizationTokenKind, AuthorizationTokenSnapshot> tokens,
			OAuth2Authorization.Token<OidcIdToken> token) {
		if (token == null) {
			return;
		}
		Map<String, Object> claims = validateMetadata(token, true, false);
		OidcIdToken value = token.getToken();
		validateToken(value.getTokenValue(), value.getIssuedAt(), value.getExpiresAt());
		Instant issuedAt = AuthorizationTime.toDatabasePrecision(value.getIssuedAt());
		Instant expiresAt = AuthorizationTime.toDatabasePrecision(value.getExpiresAt());
		validateToken(value.getTokenValue(), issuedAt, expiresAt);
		if (claims.isEmpty() || !claims.equals(value.getClaims())) {
			throw new IllegalArgumentException("ID token claims metadata must match the ID token");
		}
		tokens.put(AuthorizationTokenKind.ID_TOKEN,
				new AuthorizationTokenSnapshot(value.getTokenValue(), issuedAt, expiresAt,
					token.isInvalidated(), null, Set.of(), claims));
	}

	private static Map<String, Object> validateMetadata(OAuth2Authorization.Token<?> token, boolean claimsRequired) {
		return validateMetadata(token, claimsRequired, false);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> validateMetadata(OAuth2Authorization.Token<?> token, boolean claimsRequired,
			boolean accessToken) {
		Set<String> allowed = accessToken
				? Set.of(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
						OAuth2Authorization.Token.CLAIMS_METADATA_NAME, OAuth2TokenFormat.class.getName())
				: claimsRequired
						? Set.of(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
								OAuth2Authorization.Token.CLAIMS_METADATA_NAME)
						: Set.of(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
		if (!allowed.equals(token.getMetadata().keySet())
				|| !(token.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME) instanceof Boolean)) {
			throw new IllegalArgumentException("Authorization token contains unsupported metadata");
		}
		if (accessToken && !OAuth2TokenFormat.SELF_CONTAINED.getValue()
			.equals(token.getMetadata(OAuth2TokenFormat.class.getName()))) {
			throw new IllegalArgumentException("Only self-contained access tokens are supported");
		}
		if (!claimsRequired) {
			return null;
		}
		Object claims = token.getMetadata().get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
		if (!(claims instanceof Map<?, ?> map)
				|| !map.keySet().stream().allMatch(String.class::isInstance)) {
			throw new IllegalArgumentException("Authorization token claims metadata is required");
		}
		return Collections.unmodifiableMap(new LinkedHashMap<>((Map<String, Object>) claims));
	}

	private static void validateToken(String value, java.time.Instant issuedAt, java.time.Instant expiresAt) {
		if (value == null || value.isEmpty() || value.length() > MAXIMUM_TOKEN_VALUE_LENGTH) {
			throw new IllegalArgumentException("Authorization token value must contain 1 to 24576 characters");
		}
		if (issuedAt == null || expiresAt == null || !expiresAt.isAfter(issuedAt)) {
			throw new IllegalArgumentException("Authorization token timestamps are invalid");
		}
	}

	private static OAuth2Authorization sanitizedAuthorizationCode(OAuth2Authorization original,
			AuthorizationSnapshot snapshot, AuthorizationUserAuthentication authentication,
			OAuth2AuthorizationRequest request) {
		RegisteredClient.Builder registeredClient = RegisteredClient.withId(original.getRegisteredClientId())
			.clientId(snapshot.clientIdentifier())
			.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		if (snapshot.tokens().containsKey(AuthorizationTokenKind.REFRESH_TOKEN)) {
			registeredClient.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
		}
		if (snapshot.redirectUri() != null) {
			registeredClient.redirectUri(snapshot.redirectUri());
		}
		snapshot.requestedScopes().forEach(registeredClient::scope);
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient.build())
			.id(snapshot.authorizationId().toString())
			.principalName(snapshot.principal().getName())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizedScopes(snapshot.authorizedScopes())
			.attribute(Principal.class.getName(), authentication)
			.attribute(OAuth2AuthorizationRequest.class.getName(), request);
		if (snapshot.consentState() != null) {
			builder.attribute(OAuth2ParameterNames.STATE, snapshot.consentState());
		}
		if (snapshot.expectedVersion() != null) {
			builder.attribute(REVISION_ATTRIBUTE, snapshot.expectedVersion());
		}
		OAuth2Authorization.Token<OAuth2AuthorizationCode> code =
				original.getToken(OAuth2AuthorizationCode.class);
		if (code != null) {
			builder.token(code.getToken(), metadata -> metadata.putAll(code.getMetadata()));
		}
		OAuth2Authorization.Token<OAuth2AccessToken> access = original.getAccessToken();
		if (access != null) {
			builder.token(access.getToken(), metadata -> metadata.putAll(access.getMetadata()));
		}
		OAuth2Authorization.Token<OAuth2RefreshToken> refresh = original.getRefreshToken();
		if (refresh != null) {
			builder.token(refresh.getToken(), metadata -> metadata.putAll(refresh.getMetadata()));
		}
		OAuth2Authorization.Token<OidcIdToken> id = original.getToken(OidcIdToken.class);
		if (id != null) {
			builder.token(id.getToken(), metadata -> metadata.putAll(id.getMetadata()));
		}
		return builder.build();
	}

	private static OAuth2Authorization sanitizedClientCredentialsAuthorization(OAuth2Authorization original,
			AuthorizationSnapshot snapshot) {
		RegisteredClient.Builder registeredClient = RegisteredClient.withId(original.getRegisteredClientId())
			.clientId(snapshot.clientIdentifier())
			.clientAuthenticationMethod(
					org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		snapshot.requestedScopes().forEach(registeredClient::scope);
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient.build())
			.id(snapshot.authorizationId().toString())
			.principalName(snapshot.principalName())
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizedScopes(snapshot.authorizedScopes());
		if (snapshot.expectedVersion() != null) {
			builder.attribute(REVISION_ATTRIBUTE, snapshot.expectedVersion());
		}
		OAuth2Authorization.Token<OAuth2AccessToken> access = original.getAccessToken();
		if (access != null) {
			builder.token(access.getToken(), metadata -> metadata.putAll(access.getMetadata()));
		}
		return builder.build();
	}

	private static Long revision(Object value) {
		if (value == null) {
			return null;
		}
		if (!(value instanceof Number number)) {
			throw new IllegalArgumentException("Authorization revision must be a non-negative integer");
		}
		long revision = number.longValue();
		if (revision < 0 || number.doubleValue() != revision) {
			throw new IllegalArgumentException("Authorization revision must be a non-negative integer");
		}
		return revision;
	}

	private static String optionalString(Object value, String name) {
		if (value == null) {
			return null;
		}
		if (!(value instanceof String text) || text.isEmpty() || text.length() > 24_576) {
			throw new IllegalArgumentException(name + " must contain 1 to 24576 characters");
		}
		return text;
	}

	private static UUID parseUuid(String value, String name) {
		try {
			return UUID.fromString(value);
		}
		catch (RuntimeException exception) {
			throw new IllegalArgumentException(name + " must be a UUID", exception);
		}
	}

}
