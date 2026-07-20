package com.ixayda.iam.authorization.internal;

import java.security.Principal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
class JdbcOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private static final int REQUEST_VERSION = 1;

	private static final int CLAIMS_VERSION = 1;

	private static final int MAXIMUM_TOKEN_VALUE_LENGTH = 24_576;

	private final JdbcClient jdbcClient;

	private final AuthorizationSnapshotMapper mapper;

	private final AuthorizationTokenCipher tokenCipher;

	private final AuthorizationPersistenceProperties properties;

	private final Clock clock;

	JdbcOAuth2AuthorizationService(JdbcClient jdbcClient, AuthorizationSnapshotMapper mapper,
			AuthorizationTokenCipher tokenCipher, AuthorizationPersistenceProperties properties) {
		this(jdbcClient, mapper, tokenCipher, properties, Clock.systemUTC());
	}

	JdbcOAuth2AuthorizationService(JdbcClient jdbcClient, AuthorizationSnapshotMapper mapper,
			AuthorizationTokenCipher tokenCipher, AuthorizationPersistenceProperties properties, Clock clock) {
		this.jdbcClient = Objects.requireNonNull(jdbcClient, "JDBC client must not be null");
		this.mapper = Objects.requireNonNull(mapper, "Authorization snapshot mapper must not be null");
		this.tokenCipher = Objects.requireNonNull(tokenCipher, "Authorization token cipher must not be null");
		this.properties = Objects.requireNonNull(properties, "Authorization persistence properties must not be null");
		this.clock = Objects.requireNonNull(clock, "Authorization clock must not be null");
	}

	@Override
	@Transactional
	public void save(OAuth2Authorization authorization) {
		AuthorizationSnapshot snapshot = snapshot(authorization);
		Instant now = AuthorizationTime.toDatabasePrecision(this.clock.instant());
		StoredAuthorization current = lock(snapshot.authorizationId());
		if (current == null) {
			insert(snapshot, now);
			return;
		}
		update(current, snapshot, now);
	}

	@Override
	@Transactional
	public void remove(OAuth2Authorization authorization) {
		removeIfCurrent(authorization);
	}

	@Transactional
	public boolean removeIfCurrent(OAuth2Authorization authorization) {
		AuthorizationSnapshot snapshot = snapshot(authorization);
		StoredAuthorization current = lock(snapshot.authorizationId());
		if (current == null) {
			return false;
		}
		long expectedVersion = snapshot.expectedVersion() == null ? 0 : snapshot.expectedVersion();
		if (current.version() != expectedVersion || !hasSameImmutableState(current, snapshot)) {
			return false;
		}
		int affected = this.jdbcClient.sql("""
				DELETE FROM oauth_authorizations
				WHERE authorization_id = :authorizationId AND version = :version
				""")
			.param("authorizationId", snapshot.authorizationId())
			.param("version", expectedVersion)
			.update();
		return affected == 1;
	}

	@Override
	public OAuth2Authorization findById(String id) {
		UUID authorizationId = parseOptionalUuid(id);
		return authorizationId == null ? null : load(authorizationId);
	}

	private AuthorizationSnapshot snapshot(OAuth2Authorization authorization) {
		if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(authorization.getAuthorizationGrantType())) {
			return this.mapper.toSnapshot(authorization);
		}
		UUID clientId = parseOptionalUuid(authorization.getRegisteredClientId());
		String clientIdentifier = authorization.getPrincipalName();
		if (clientId == null || clientIdentifier == null || clientIdentifier.isEmpty()) {
			throw new IllegalArgumentException("Client-credentials authorization identity is invalid");
		}
		UUID tenantId = this.jdbcClient.sql("""
				SELECT tenant_id
				FROM oauth_clients
				WHERE client_id = :clientId
				  AND client_identifier = :clientIdentifier
				  AND authorization_grant_type = 'client_credentials'
				""")
			.param("clientId", clientId)
			.param("clientIdentifier", clientIdentifier)
			.query(UUID.class)
			.optional()
			.orElse(null);
		if (tenantId == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
		return this.mapper.toSnapshot(authorization, tenantId);
	}

	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
		if (token == null || token.isEmpty() || token.length() > MAXIMUM_TOKEN_VALUE_LENGTH) {
			throw new IllegalArgumentException("Token must contain 1 to 24576 characters");
		}
		AuthorizationTokenKind kind = tokenType == null ? null : tokenKind(tokenType);
		if (tokenType != null && kind == null) {
			return null;
		}
		byte[] digest = this.tokenCipher.digest(token);
		UUID authorizationId = this.jdbcClient.sql("""
				SELECT authorization_id
				FROM oauth_authorization_tokens
				WHERE token_digest = :digest
				  AND (CAST(:tokenType AS text) IS NULL OR token_type = :tokenType)
				  AND (
				      token_type <> 'state'
				      OR (invalidated_at IS NULL AND expires_at > now())
				  )
				""")
			.param("digest", digest)
			.param("tokenType", kind == null ? null : kind.databaseValue())
			.query(UUID.class)
			.optional()
			.orElse(null);
		return authorizationId == null ? null : load(authorizationId);
	}

	private void insert(AuthorizationSnapshot snapshot, Instant now) {
		if (snapshot.expectedVersion() != null) {
			throw concurrentUpdate();
		}
		ensureOwnerIsUsable(snapshot, now);
		Map<AuthorizationTokenKind, DesiredToken> desiredTokens = desiredTokens(snapshot, now, Map.of());
		Instant purgeAt = purgeAt(desiredTokens, now);
		int affected = this.jdbcClient.sql("""
				INSERT INTO oauth_authorizations
				    (authorization_id, tenant_id, client_id, user_id, session_id,
				     client_identifier, principal_name, authorization_grant_type,
				     authorization_uri, redirect_uri, client_state, request_version,
				     request_parameters, version, created_at, updated_at, purge_at)
				VALUES
				    (:authorizationId, :tenantId, :clientId, CAST(:userId AS uuid), CAST(:sessionId AS uuid),
				     :clientIdentifier, :principalName, :authorizationGrantType,
				     CAST(:authorizationUri AS text), :redirectUri, :clientState, :requestVersion,
				     CAST(:requestParameters AS jsonb), 0, :now, :now, :purgeAt)
				""")
			.param("authorizationId", snapshot.authorizationId())
			.param("tenantId", snapshot.tenantId())
			.param("clientId", snapshot.clientId())
			.param("userId", snapshot.principal() == null ? null : snapshot.principal().userId().value())
			.param("sessionId", snapshot.principal() == null ? null : snapshot.principal().sessionId().value())
			.param("clientIdentifier", snapshot.clientIdentifier())
			.param("principalName", snapshot.principalName())
			.param("authorizationGrantType", snapshot.grantType().databaseValue())
			.param("authorizationUri", snapshot.authorizationUri())
			.param("redirectUri", snapshot.redirectUri())
			.param("clientState", snapshot.clientState())
			.param("requestVersion", REQUEST_VERSION)
			.param("requestParameters", this.mapper.encodeRequestParameters(snapshot.requestParameters()))
			.param("now", offset(now))
			.param("purgeAt", offset(purgeAt))
			.update();
		if (affected != 1) {
			throw new IllegalStateException("Inserting an authorization affected an unexpected number of rows: " + affected);
		}
		insertRequestedScopes(snapshot);
		insertAuthorizedScopes(snapshot, now);
		insertPrincipalAuthorities(snapshot);
		for (Map.Entry<AuthorizationTokenKind, DesiredToken> token : desiredTokens.entrySet()) {
			insertToken(snapshot, token.getKey(), token.getValue(), now);
		}
	}

	private void update(StoredAuthorization current, AuthorizationSnapshot snapshot, Instant now) {
		if (snapshot.expectedVersion() == null || current.version() != snapshot.expectedVersion()) {
			throw concurrentUpdate();
		}
		if (!hasSameImmutableState(current, snapshot)) {
			throw new IllegalArgumentException("Persisted authorization identity and request state are immutable");
		}
		ensureOwnerIsUsable(snapshot, now);
		Map<AuthorizationTokenKind, StoredToken> storedTokens = loadTokens(current);
		Map<AuthorizationTokenKind, DesiredToken> desiredTokens = desiredTokens(snapshot, now, storedTokens);
		Instant purgeAt = purgeAt(desiredTokens, now);
		int affected = this.jdbcClient.sql("""
				UPDATE oauth_authorizations
				SET version = version + 1,
				    updated_at = :now,
				    purge_at = GREATEST(purge_at, :purgeAt)
				WHERE authorization_id = :authorizationId AND version = :version
				""")
			.param("now", offset(now))
			.param("purgeAt", offset(purgeAt))
			.param("authorizationId", current.authorizationId())
			.param("version", current.version())
			.update();
		if (affected != 1) {
			throw concurrentUpdate();
		}
		synchronizeAuthorizedScopes(current, snapshot, now);
		synchronizeTokens(snapshot, storedTokens, desiredTokens, now);
	}

	private void ensureOwnerIsUsable(AuthorizationSnapshot snapshot, Instant now) {
		switch (snapshot.grantType()) {
			case AUTHORIZATION_CODE -> ensureUserOwnerIsUsable(snapshot, now);
			case CLIENT_CREDENTIALS -> ensureClientOwnerIsUsable(snapshot);
		}
	}

	private void ensureUserOwnerIsUsable(AuthorizationSnapshot snapshot, Instant now) {
		Integer usable = this.jdbcClient.sql("""
				SELECT 1
				FROM oauth_clients clients
				JOIN tenants ON tenants.tenant_id = clients.tenant_id
				JOIN users
				  ON users.tenant_id = clients.tenant_id
				 AND users.user_id = :userId
				JOIN user_sessions sessions
				  ON sessions.tenant_id = users.tenant_id
				 AND sessions.user_id = users.user_id
				 AND sessions.session_id = :sessionId
				WHERE clients.tenant_id = :tenantId
				  AND clients.client_id = :clientId
				  AND clients.client_identifier = :clientIdentifier
				  AND clients.status = 'active'
				  AND tenants.status = 'active'
				  AND users.status = 'active'
				  AND sessions.status = 'active'
				  AND sessions.expires_at > :now
				  AND sessions.issued_tenant_version = tenants.version
				  AND sessions.issued_user_version = users.security_version
				  AND sessions.authentication_method = :authenticationMethod
				  AND sessions.authenticated_at = :authenticatedAt
				FOR SHARE OF clients, tenants, users, sessions
				""")
			.param("tenantId", snapshot.tenantId())
			.param("clientId", snapshot.clientId())
			.param("clientIdentifier", snapshot.clientIdentifier())
			.param("userId", snapshot.principal().userId().value())
			.param("sessionId", snapshot.principal().sessionId().value())
			.param("now", offset(now))
			.param("authenticationMethod", snapshot.principal().authenticationMethod().name().toLowerCase())
			.param("authenticatedAt", offset(snapshot.principal().authenticatedAt()))
			.query(Integer.class)
			.optional()
			.orElse(null);
		if (usable == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
	}

	private void ensureClientOwnerIsUsable(AuthorizationSnapshot snapshot) {
		Integer usable = this.jdbcClient.sql("""
				SELECT 1
				FROM oauth_clients clients
				JOIN tenants ON tenants.tenant_id = clients.tenant_id
				WHERE clients.tenant_id = :tenantId
				  AND clients.client_id = :clientId
				  AND clients.client_identifier = :clientIdentifier
				  AND clients.authorization_grant_type = 'client_credentials'
				  AND clients.status = 'active'
				  AND tenants.status = 'active'
				FOR SHARE OF clients, tenants
				""")
			.param("tenantId", snapshot.tenantId())
			.param("clientId", snapshot.clientId())
			.param("clientIdentifier", snapshot.clientIdentifier())
			.query(Integer.class)
			.optional()
			.orElse(null);
		if (usable == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}
	}

	private boolean hasSameImmutableState(StoredAuthorization current, AuthorizationSnapshot snapshot) {
		if (!current.tenantId().equals(snapshot.tenantId()) || !current.clientId().equals(snapshot.clientId())
				|| current.grantType() != snapshot.grantType()
				|| !current.clientIdentifier().equals(snapshot.clientIdentifier())
				|| !current.principalName().equals(snapshot.principalName())
				|| !Objects.equals(current.authorizationUri(), snapshot.authorizationUri())
				|| !Objects.equals(current.redirectUri(), snapshot.redirectUri())
				|| !Objects.equals(current.clientState(), snapshot.clientState())
				|| current.requestVersion() != REQUEST_VERSION
				|| !this.mapper.decodeJson(current.requestParameters()).equals(snapshot.requestParameters())
				|| !loadRequestedScopes(current).equals(snapshot.requestedScopes())
				|| !loadPrincipalAuthorities(current).equals(snapshot.principalAuthorities())) {
			return false;
		}
		return switch (snapshot.grantType()) {
			case AUTHORIZATION_CODE -> current.userId().equals(snapshot.principal().userId().value())
					&& current.sessionId().equals(snapshot.principal().sessionId().value())
					&& current.authenticationMethod()
						.equals(snapshot.principal().authenticationMethod().name().toLowerCase())
					&& current.authenticatedAt().equals(snapshot.principal().authenticatedAt());
			case CLIENT_CREDENTIALS -> current.userId() == null && current.sessionId() == null
					&& current.authenticationMethod() == null && current.authenticatedAt() == null;
		};
	}

	private void insertRequestedScopes(AuthorizationSnapshot snapshot) {
		for (String scope : snapshot.requestedScopes()) {
			this.jdbcClient.sql("""
					INSERT INTO oauth_authorization_requested_scopes
					    (tenant_id, client_id, authorization_id, scope)
					VALUES (:tenantId, :clientId, :authorizationId, :scope)
					""")
				.param("tenantId", snapshot.tenantId())
				.param("clientId", snapshot.clientId())
				.param("authorizationId", snapshot.authorizationId())
				.param("scope", scope)
				.update();
		}
	}

	private void synchronizeAuthorizedScopes(StoredAuthorization current, AuthorizationSnapshot snapshot, Instant now) {
		Set<String> storedScopes = loadAuthorizedScopes(current);
		for (String scope : storedScopes) {
			if (!snapshot.authorizedScopes().contains(scope)) {
				this.jdbcClient.sql("""
						DELETE FROM oauth_authorization_scopes
						WHERE tenant_id = :tenantId AND client_id = :clientId
						  AND authorization_id = :authorizationId AND scope = :scope
						""")
					.param("tenantId", snapshot.tenantId())
					.param("clientId", snapshot.clientId())
					.param("authorizationId", snapshot.authorizationId())
					.param("scope", scope)
					.update();
			}
		}
		for (String scope : snapshot.authorizedScopes()) {
			if (!storedScopes.contains(scope)) {
				insertAuthorizedScope(snapshot, scope, now);
			}
		}
	}

	private void insertAuthorizedScopes(AuthorizationSnapshot snapshot, Instant now) {
		for (String scope : snapshot.authorizedScopes()) {
			insertAuthorizedScope(snapshot, scope, now);
		}
	}

	private void insertAuthorizedScope(AuthorizationSnapshot snapshot, String scope, Instant now) {
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_scopes
				    (tenant_id, client_id, authorization_id, scope, granted_at)
				VALUES (:tenantId, :clientId, :authorizationId, :scope, :grantedAt)
				""")
			.param("tenantId", snapshot.tenantId())
			.param("clientId", snapshot.clientId())
			.param("authorizationId", snapshot.authorizationId())
			.param("scope", scope)
			.param("grantedAt", offset(now))
			.update();
	}

	private void insertPrincipalAuthorities(AuthorizationSnapshot snapshot) {
		for (AuthorizationAuthoritySnapshot authority : snapshot.principalAuthorities()) {
			this.jdbcClient.sql("""
					INSERT INTO oauth_authorization_principal_authorities
					    (tenant_id, client_id, authorization_id, authority, issued_at)
					VALUES (:tenantId, :clientId, :authorizationId, :authority, CAST(:issuedAt AS timestamptz))
					""")
				.param("tenantId", snapshot.tenantId())
				.param("clientId", snapshot.clientId())
				.param("authorizationId", snapshot.authorizationId())
				.param("authority", authority.authority())
				.param("issuedAt", offset(authority.issuedAt()))
				.update();
		}
	}

	private Map<AuthorizationTokenKind, DesiredToken> desiredTokens(AuthorizationSnapshot snapshot, Instant now,
			Map<AuthorizationTokenKind, StoredToken> storedTokens) {
		Map<AuthorizationTokenKind, DesiredToken> desired = new EnumMap<>(AuthorizationTokenKind.class);
		if (snapshot.consentState() != null) {
			StoredToken storedState = storedTokens.get(AuthorizationTokenKind.STATE);
			Instant issuedAt = storedState == null ? now : storedState.issuedAt();
			Instant expiresAt = storedState == null ? now.plus(this.properties.pendingAuthorizationTtl())
					: storedState.expiresAt();
			desired.put(AuthorizationTokenKind.STATE,
					new DesiredToken(snapshot.consentState(), issuedAt, expiresAt, false, null, Set.of(), null));
		}
		snapshot.tokens().forEach((kind, token) -> desired.put(kind,
				new DesiredToken(token.value(), token.issuedAt(), token.expiresAt(), token.invalidated(),
					token.accessTokenType(), token.scopes(), token.claims())));
		if (desired.isEmpty()) {
			throw new IllegalArgumentException("Authorization must contain consent state or a supported token");
		}
		return desired;
	}

	private Instant purgeAt(Map<AuthorizationTokenKind, DesiredToken> tokens, Instant now) {
		Instant latestExpiry = tokens.values().stream().map(DesiredToken::expiresAt).max(Instant::compareTo)
			.orElseGet(() -> now.plus(this.properties.pendingAuthorizationTtl()));
		return latestExpiry.plus(this.properties.tokenRetention());
	}

	private void synchronizeTokens(AuthorizationSnapshot snapshot,
			Map<AuthorizationTokenKind, StoredToken> storedTokens,
			Map<AuthorizationTokenKind, DesiredToken> desiredTokens, Instant now) {
		StoredToken storedRefresh = storedTokens.get(AuthorizationTokenKind.REFRESH_TOKEN);
		DesiredToken desiredRefresh = desiredTokens.get(AuthorizationTokenKind.REFRESH_TOKEN);
		boolean refreshing = storedRefresh != null && desiredRefresh != null && !storedRefresh.invalidated()
				&& !desiredRefresh.invalidated() && !hasSamePayload(storedRefresh, desiredRefresh);
		if (refreshing) {
			StoredToken storedAccess = storedTokens.get(AuthorizationTokenKind.ACCESS_TOKEN);
			DesiredToken desiredAccess = desiredTokens.get(AuthorizationTokenKind.ACCESS_TOKEN);
			if (storedAccess == null || desiredAccess == null || hasSamePayload(storedAccess, desiredAccess)) {
				throw new IllegalArgumentException("Refresh-token rotation requires a new access token");
			}
		}
		for (Map.Entry<AuthorizationTokenKind, StoredToken> stored : storedTokens.entrySet()) {
			DesiredToken desired = desiredTokens.get(stored.getKey());
			if (desired == null) {
				if (stored.getKey() != AuthorizationTokenKind.STATE) {
					throw new IllegalArgumentException("Persisted protocol tokens cannot be removed from an authorization");
				}
				deleteToken(stored.getValue());
				continue;
			}
			if (refreshing && isRenewable(stored.getKey()) && !hasSamePayload(stored.getValue(), desired)) {
				deleteToken(stored.getValue());
				insertToken(snapshot, stored.getKey(), desired, now);
				continue;
			}
			updateToken(stored.getValue(), desired, now);
		}
		for (Map.Entry<AuthorizationTokenKind, DesiredToken> desired : desiredTokens.entrySet()) {
			if (!storedTokens.containsKey(desired.getKey())) {
				insertToken(snapshot, desired.getKey(), desired.getValue(), now);
			}
		}
	}

	private void insertToken(AuthorizationSnapshot authorization, AuthorizationTokenKind kind, DesiredToken token,
			Instant now) {
		UUID tokenId = UUID.randomUUID();
		AuthorizationTokenCipher.TokenContext context = new AuthorizationTokenCipher.TokenContext(
				authorization.tenantId(), authorization.clientId(), authorization.authorizationId(), tokenId,
				kind.databaseValue());
		AuthorizationTokenCipher.ProtectedToken protectedToken = this.tokenCipher.protect(token.value(), context);
		String claims = token.claims() == null ? null : this.mapper.encodeClaims(token.claims());
		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_tokens
				    (token_id, tenant_id, client_id, authorization_id, authorization_grant_type, token_type,
				     token_digest, encryption_key_id, initialization_vector, ciphertext,
				     access_token_type, claims_version, claims, issued_at, expires_at,
				     invalidated_at, version, created_at, updated_at)
				VALUES
				    (:tokenId, :tenantId, :clientId, :authorizationId, :authorizationGrantType, :tokenType,
				     :tokenDigest, :keyId, :initializationVector, :ciphertext,
				     :accessTokenType, :claimsVersion, CAST(:claims AS jsonb), :issuedAt, :expiresAt,
				     :invalidatedAt, 0, :now, :now)
				""")
			.param("tokenId", tokenId)
			.param("tenantId", authorization.tenantId())
			.param("clientId", authorization.clientId())
			.param("authorizationId", authorization.authorizationId())
			.param("authorizationGrantType", authorization.grantType().databaseValue())
			.param("tokenType", kind.databaseValue())
			.param("tokenDigest", protectedToken.digest())
			.param("keyId", protectedToken.keyId())
			.param("initializationVector", protectedToken.initializationVector())
			.param("ciphertext", protectedToken.ciphertext())
			.param("accessTokenType", token.accessTokenType())
			.param("claimsVersion", claims == null ? null : CLAIMS_VERSION)
			.param("claims", claims)
			.param("issuedAt", offset(token.issuedAt()))
			.param("expiresAt", offset(token.expiresAt()))
			.param("invalidatedAt", token.invalidated() ? offset(now) : null)
			.param("now", offset(now))
			.update();
		if (kind == AuthorizationTokenKind.ACCESS_TOKEN) {
			for (String scope : token.scopes()) {
				this.jdbcClient.sql("""
						INSERT INTO oauth_authorization_token_scopes
						    (tenant_id, client_id, authorization_id, token_id, token_type, scope)
						VALUES (:tenantId, :clientId, :authorizationId, :tokenId, 'access_token', :scope)
						""")
					.param("tenantId", authorization.tenantId())
					.param("clientId", authorization.clientId())
					.param("authorizationId", authorization.authorizationId())
					.param("tokenId", tokenId)
					.param("scope", scope)
					.update();
			}
		}
	}

	private void updateToken(StoredToken stored, DesiredToken desired, Instant now) {
		if (!hasSamePayload(stored, desired)) {
			throw new IllegalArgumentException("Persisted authorization token payload is immutable");
		}
		if (stored.invalidated() && !desired.invalidated()) {
			throw new IllegalArgumentException("Persisted authorization token invalidation cannot be reversed");
		}
		if (!stored.invalidated() && desired.invalidated()) {
			int affected = this.jdbcClient.sql("""
					UPDATE oauth_authorization_tokens
					SET invalidated_at = :invalidatedAt,
					    version = version + 1,
					    updated_at = :invalidatedAt
					WHERE token_id = :tokenId AND version = :version AND invalidated_at IS NULL
					""")
				.param("invalidatedAt", offset(now))
				.param("tokenId", stored.tokenId())
				.param("version", stored.version())
				.update();
			if (affected != 1) {
				throw concurrentUpdate();
			}
		}
	}

	private boolean hasSamePayload(StoredToken stored, DesiredToken desired) {
		return java.security.MessageDigest.isEqual(stored.digest(), this.tokenCipher.digest(desired.value()))
				&& stored.issuedAt().equals(desired.issuedAt()) && stored.expiresAt().equals(desired.expiresAt())
				&& Objects.equals(stored.accessTokenType(), desired.accessTokenType())
				&& stored.scopes().equals(desired.scopes()) && Objects.equals(stored.claims(), desired.claims());
	}

	private static boolean isRenewable(AuthorizationTokenKind kind) {
		return kind == AuthorizationTokenKind.ACCESS_TOKEN || kind == AuthorizationTokenKind.REFRESH_TOKEN
				|| kind == AuthorizationTokenKind.ID_TOKEN;
	}

	private void deleteToken(StoredToken token) {
		int affected = this.jdbcClient
			.sql("DELETE FROM oauth_authorization_tokens WHERE token_id = :tokenId AND version = :version")
			.param("tokenId", token.tokenId())
			.param("version", token.version())
			.update();
		if (affected != 1) {
			throw concurrentUpdate();
		}
	}

	private StoredAuthorization lock(UUID authorizationId) {
		return queryAuthorization("authz.authorization_id = :authorizationId FOR UPDATE OF authz",
				authorizationId);
	}

	private OAuth2Authorization load(UUID authorizationId) {
		StoredAuthorization stored = queryAuthorization("authz.authorization_id = :authorizationId",
				authorizationId);
		return stored == null ? null : toAuthorization(stored);
	}

	private StoredAuthorization queryAuthorization(String filter, UUID authorizationId) {
		return this.jdbcClient.sql("""
				SELECT authz.authorization_id, authz.tenant_id, authz.client_id,
				       authz.user_id, authz.session_id, authz.client_identifier,
				       authz.principal_name, authz.authorization_grant_type,
				       authz.authorization_uri, authz.redirect_uri,
				       authz.client_state, authz.request_version,
				       authz.request_parameters::text AS request_parameters,
				       authz.version, authz.created_at, authz.updated_at,
				       authz.purge_at, sessions.authentication_method, sessions.authenticated_at
				FROM oauth_authorizations authz
				LEFT JOIN user_sessions sessions
				  ON sessions.tenant_id = authz.tenant_id
				 AND sessions.user_id = authz.user_id
				 AND sessions.session_id = authz.session_id
				WHERE
				""" + filter)
			.param("authorizationId", authorizationId)
			.query((resultSet, rowNumber) -> storedAuthorization(resultSet))
			.optional()
			.orElse(null);
	}

	private OAuth2Authorization toAuthorization(StoredAuthorization stored) {
		Set<String> requestedScopes = loadRequestedScopes(stored);
		Set<String> authorizedScopes = loadAuthorizedScopes(stored);
		Map<String, Object> requestParameters = this.mapper.decodeJson(stored.requestParameters());
		Map<AuthorizationTokenKind, StoredToken> tokens = loadTokens(stored);
		return switch (stored.grantType()) {
			case AUTHORIZATION_CODE -> toAuthorizationCode(stored, requestedScopes, authorizedScopes, requestParameters,
					tokens);
			case CLIENT_CREDENTIALS -> toClientCredentials(stored, requestedScopes, authorizedScopes,
					requestParameters, tokens);
		};
	}

	private OAuth2Authorization toAuthorizationCode(StoredAuthorization stored, Set<String> requestedScopes,
			Set<String> authorizedScopes, Map<String, Object> requestParameters,
			Map<AuthorizationTokenKind, StoredToken> tokens) {
		OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(stored.authorizationUri())
			.clientId(stored.clientIdentifier())
			.redirectUri(stored.redirectUri())
			.scopes(requestedScopes)
			.state(stored.clientState())
			.additionalParameters(requestParameters)
			.build();
		AuthorizationPrincipal principal = new AuthorizationPrincipal(new TenantId(stored.tenantId()),
				new UserId(stored.userId()), new SessionId(stored.sessionId()),
				SessionAuthenticationMethod.valueOf(stored.authenticationMethod().toUpperCase()),
				stored.authenticatedAt());
		Set<AuthorizationAuthoritySnapshot> storedAuthorities = loadPrincipalAuthorities(stored);
		if (storedAuthorities.stream().noneMatch(authority ->
				FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(authority.authority()))) {
			throw new DataRetrievalFailureException("Stored authorization is missing its password factor authority");
		}
		AuthorizationUserAuthentication authentication = AuthorizationUserAuthentication.authenticated(principal,
				storedAuthorities.stream().map(authority -> storedAuthority(authority, principal)).toList());
		RegisteredClient.Builder registeredClient = RegisteredClient.withId(stored.clientId().toString())
			.clientId(stored.clientIdentifier())
			.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		if (tokens.containsKey(AuthorizationTokenKind.REFRESH_TOKEN)) {
			registeredClient.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
		}
		if (stored.redirectUri() != null) {
			registeredClient.redirectUri(stored.redirectUri());
		}
		requestedScopes.forEach(registeredClient::scope);
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient.build())
			.id(stored.authorizationId().toString())
			.principalName(stored.principalName())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizedScopes(authorizedScopes)
			.attribute(Principal.class.getName(), authentication)
			.attribute(OAuth2AuthorizationRequest.class.getName(), request)
			.attribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE, stored.version());

		StoredToken state = tokens.get(AuthorizationTokenKind.STATE);
		if (state != null) {
			builder.attribute(OAuth2ParameterNames.STATE, reveal(stored, state));
		}
		StoredToken code = tokens.get(AuthorizationTokenKind.AUTHORIZATION_CODE);
		if (code != null) {
			OAuth2AuthorizationCode value = new OAuth2AuthorizationCode(reveal(stored, code), code.issuedAt(),
					code.expiresAt());
			builder.token(value, metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
					code.invalidated()));
		}
		StoredToken access = tokens.get(AuthorizationTokenKind.ACCESS_TOKEN);
		if (access != null) {
			OAuth2AccessToken.TokenType type = OAuth2AccessToken.TokenType.BEARER.getValue()
				.equals(access.accessTokenType()) ? OAuth2AccessToken.TokenType.BEARER : OAuth2AccessToken.TokenType.DPOP;
			OAuth2AccessToken value = new OAuth2AccessToken(type, reveal(stored, access), access.issuedAt(),
					access.expiresAt(), access.scopes());
			builder.token(value, metadata -> {
				metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, access.invalidated());
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, access.claims());
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			});
		}
		StoredToken refresh = tokens.get(AuthorizationTokenKind.REFRESH_TOKEN);
		if (refresh != null) {
			OAuth2RefreshToken value = new OAuth2RefreshToken(reveal(stored, refresh), refresh.issuedAt(),
					refresh.expiresAt());
			builder.token(value, metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME,
					refresh.invalidated()));
		}
		StoredToken id = tokens.get(AuthorizationTokenKind.ID_TOKEN);
		if (id != null) {
			OidcIdToken value = new OidcIdToken(reveal(stored, id), id.issuedAt(), id.expiresAt(), id.claims());
			builder.token(value, metadata -> {
				metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, id.invalidated());
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, id.claims());
			});
		}
		OAuth2Authorization authorization = builder.build();
		this.mapper.toSnapshot(authorization);
		return authorization;
	}

	private OAuth2Authorization toClientCredentials(StoredAuthorization stored, Set<String> requestedScopes,
			Set<String> authorizedScopes, Map<String, Object> requestParameters,
			Map<AuthorizationTokenKind, StoredToken> tokens) {
		if (!requestParameters.isEmpty() || !requestedScopes.equals(authorizedScopes)
				|| !loadPrincipalAuthorities(stored).isEmpty()
				|| !tokens.keySet().equals(Set.of(AuthorizationTokenKind.ACCESS_TOKEN))) {
			throw new DataRetrievalFailureException("Stored client-credentials authorization has invalid protocol state");
		}
		RegisteredClient.Builder registeredClient = RegisteredClient.withId(stored.clientId().toString())
			.clientId(stored.clientIdentifier())
			.clientAuthenticationMethod(
					org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		requestedScopes.forEach(registeredClient::scope);
		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient.build())
			.id(stored.authorizationId().toString())
			.principalName(stored.principalName())
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizedScopes(authorizedScopes)
			.attribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE, stored.version());
		addAccessToken(builder, stored, tokens.get(AuthorizationTokenKind.ACCESS_TOKEN));
		OAuth2Authorization authorization = builder.build();
		this.mapper.toSnapshot(authorization, stored.tenantId());
		return authorization;
	}

	private void addAccessToken(OAuth2Authorization.Builder builder, StoredAuthorization stored, StoredToken access) {
		OAuth2AccessToken.TokenType type = OAuth2AccessToken.TokenType.BEARER.getValue()
			.equals(access.accessTokenType()) ? OAuth2AccessToken.TokenType.BEARER : OAuth2AccessToken.TokenType.DPOP;
		OAuth2AccessToken value = new OAuth2AccessToken(type, reveal(stored, access), access.issuedAt(),
				access.expiresAt(), access.scopes());
		builder.token(value, metadata -> {
			metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, access.invalidated());
			metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, access.claims());
			metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
		});
	}

	private String reveal(StoredAuthorization authorization, StoredToken token) {
		AuthorizationTokenCipher.TokenContext context = new AuthorizationTokenCipher.TokenContext(
				authorization.tenantId(), authorization.clientId(), authorization.authorizationId(), token.tokenId(),
				token.kind().databaseValue());
		return this.tokenCipher.reveal(new AuthorizationTokenCipher.ProtectedToken(token.digest(), token.keyId(),
				token.initializationVector(), token.ciphertext()), context);
	}

	private Set<String> loadRequestedScopes(StoredAuthorization stored) {
		return loadStrings("oauth_authorization_requested_scopes", "scope", stored);
	}

	private Set<String> loadAuthorizedScopes(StoredAuthorization stored) {
		return loadStrings("oauth_authorization_scopes", "scope", stored);
	}

	private Set<AuthorizationAuthoritySnapshot> loadPrincipalAuthorities(StoredAuthorization stored) {
		List<AuthorizationAuthoritySnapshot> values = this.jdbcClient.sql("""
				SELECT authority, issued_at
				FROM oauth_authorization_principal_authorities
				WHERE tenant_id = :tenantId AND client_id = :clientId AND authorization_id = :authorizationId
				ORDER BY authority
				""")
			.param("tenantId", stored.tenantId())
			.param("clientId", stored.clientId())
			.param("authorizationId", stored.authorizationId())
			.query((resultSet, rowNumber) -> new AuthorizationAuthoritySnapshot(
					resultSet.getString("authority"), instantOrNull(resultSet, "issued_at")))
			.list();
		return Collections.unmodifiableSet(new LinkedHashSet<>(values));
	}

	private static GrantedAuthority storedAuthority(AuthorizationAuthoritySnapshot authority,
			AuthorizationPrincipal principal) {
		if ((FactorGrantedAuthority.PASSWORD_AUTHORITY.equals(authority.authority())
				|| FactorGrantedAuthority.OTT_AUTHORITY.equals(authority.authority()))
				&& principal.authenticationMethod() == SessionAuthenticationMethod.PASSWORD) {
			if (authority.issuedAt().isAfter(principal.authenticatedAt())) {
				throw new DataRetrievalFailureException(
						"Stored authorization factor was issued after session authentication");
			}
			return FactorGrantedAuthority.withAuthority(authority.authority()).issuedAt(authority.issuedAt()).build();
		}
		if (authority.authority().startsWith("FACTOR_")) {
			throw new DataRetrievalFailureException("Stored authorization contains an unsupported factor authority");
		}
		return new SimpleGrantedAuthority(authority.authority());
	}

	private Set<String> loadStrings(String table, String column, StoredAuthorization stored) {
		String sql = "SELECT " + column + " FROM " + table + "\n"
				+ "WHERE tenant_id = :tenantId AND client_id = :clientId AND authorization_id = :authorizationId\n"
				+ "ORDER BY " + column;
		List<String> values = this.jdbcClient.sql(sql)
			.param("tenantId", stored.tenantId())
			.param("clientId", stored.clientId())
			.param("authorizationId", stored.authorizationId())
			.query(String.class)
			.list();
		return Collections.unmodifiableSet(new LinkedHashSet<>(values));
	}

	private Map<AuthorizationTokenKind, StoredToken> loadTokens(StoredAuthorization authorization) {
		List<StoredToken> tokens = this.jdbcClient.sql("""
				SELECT token_id, token_type, token_digest, encryption_key_id, initialization_vector,
				       ciphertext, access_token_type, claims_version, claims::text AS claims,
				       issued_at, expires_at, invalidated_at, version
				FROM oauth_authorization_tokens
				WHERE tenant_id = :tenantId AND client_id = :clientId AND authorization_id = :authorizationId
				ORDER BY token_type
				""")
			.param("tenantId", authorization.tenantId())
			.param("clientId", authorization.clientId())
			.param("authorizationId", authorization.authorizationId())
			.query((resultSet, rowNumber) -> storedToken(resultSet))
			.list();
		Map<AuthorizationTokenKind, StoredToken> mapped = new EnumMap<>(AuthorizationTokenKind.class);
		for (StoredToken token : tokens) {
			Set<String> scopes = token.kind() == AuthorizationTokenKind.ACCESS_TOKEN
					? loadTokenScopes(authorization, token.tokenId()) : Set.of();
			Map<String, Object> claims = token.claimsJson() == null ? null
					: this.mapper.decodeJson(token.claimsJson());
			StoredToken complete = token.withPayload(scopes, claims);
			if (mapped.put(complete.kind(), complete) != null) {
				throw new DataRetrievalFailureException("Authorization contains duplicate stored token types");
			}
		}
		return Collections.unmodifiableMap(mapped);
	}

	private Set<String> loadTokenScopes(StoredAuthorization authorization, UUID tokenId) {
		List<String> scopes = this.jdbcClient.sql("""
				SELECT scope
				FROM oauth_authorization_token_scopes
				WHERE tenant_id = :tenantId AND client_id = :clientId
				  AND authorization_id = :authorizationId AND token_id = :tokenId
				ORDER BY scope
				""")
			.param("tenantId", authorization.tenantId())
			.param("clientId", authorization.clientId())
			.param("authorizationId", authorization.authorizationId())
			.param("tokenId", tokenId)
			.query(String.class)
			.list();
		return Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
	}

	private static StoredAuthorization storedAuthorization(ResultSet resultSet) throws SQLException {
		String grantType = resultSet.getString("authorization_grant_type");
		AuthorizationGrantKind grant;
		try {
			grant = AuthorizationGrantKind.fromDatabaseValue(grantType);
		}
		catch (IllegalArgumentException exception) {
			throw new DataRetrievalFailureException("Stored authorization has an unsupported grant type: " + grantType);
		}
		short requestVersion = resultSet.getShort("request_version");
		if (requestVersion != REQUEST_VERSION) {
			throw new DataRetrievalFailureException(
					"Stored authorization has an unsupported request version: " + requestVersion);
		}
		UUID userId = resultSet.getObject("user_id", UUID.class);
		UUID sessionId = resultSet.getObject("session_id", UUID.class);
		String authenticationMethod = resultSet.getString("authentication_method");
		Instant authenticatedAt = instantOrNull(resultSet, "authenticated_at");
		if ((grant == AuthorizationGrantKind.AUTHORIZATION_CODE
				&& (userId == null || sessionId == null || authenticationMethod == null || authenticatedAt == null))
				|| (grant == AuthorizationGrantKind.CLIENT_CREDENTIALS
						&& (userId != null || sessionId != null || authenticationMethod != null || authenticatedAt != null))) {
			throw new DataRetrievalFailureException("Stored authorization owner does not match its grant type");
		}
		return new StoredAuthorization(resultSet.getObject("authorization_id", UUID.class),
				resultSet.getObject("tenant_id", UUID.class), resultSet.getObject("client_id", UUID.class),
				userId, sessionId, resultSet.getString("client_identifier"), resultSet.getString("principal_name"), grant,
				resultSet.getString("authorization_uri"), resultSet.getString("redirect_uri"),
				resultSet.getString("client_state"), requestVersion,
				resultSet.getString("request_parameters"), resultSet.getLong("version"),
				instant(resultSet, "created_at"), instant(resultSet, "updated_at"), instant(resultSet, "purge_at"),
				authenticationMethod, authenticatedAt);
	}

	private static StoredToken storedToken(ResultSet resultSet) throws SQLException {
		AuthorizationTokenKind kind = AuthorizationTokenKind.fromDatabaseValue(resultSet.getString("token_type"));
		String accessTokenType = resultSet.getString("access_token_type");
		Short claimsVersion = resultSet.getObject("claims_version", Short.class);
		String claims = resultSet.getString("claims");
		if (kind == AuthorizationTokenKind.ACCESS_TOKEN) {
			if (!OAuth2AccessToken.TokenType.BEARER.getValue().equals(accessTokenType)
					&& !OAuth2AccessToken.TokenType.DPOP.getValue().equals(accessTokenType)) {
				throw new DataRetrievalFailureException(
						"Stored authorization access token has an unsupported token type");
			}
		}
		else if (accessTokenType != null) {
			throw new DataRetrievalFailureException("Stored non-access token has an access token type");
		}
		boolean claimsRequired = kind == AuthorizationTokenKind.ACCESS_TOKEN || kind == AuthorizationTokenKind.ID_TOKEN;
		if ((claimsRequired && (claimsVersion == null || claimsVersion != CLAIMS_VERSION || claims == null))
				|| (!claimsRequired && (claimsVersion != null || claims != null))) {
			throw new DataRetrievalFailureException("Stored authorization token has an unsupported claims version");
		}
		return new StoredToken(resultSet.getObject("token_id", UUID.class), kind,
				resultSet.getBytes("token_digest"), resultSet.getString("encryption_key_id"),
				resultSet.getBytes("initialization_vector"), resultSet.getBytes("ciphertext"),
				accessTokenType, claims, Set.of(), null,
				instant(resultSet, "issued_at"), instant(resultSet, "expires_at"),
				resultSet.getObject("invalidated_at") != null, resultSet.getLong("version"));
	}

	private static AuthorizationTokenKind tokenKind(OAuth2TokenType tokenType) {
		if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return AuthorizationTokenKind.STATE;
		}
		if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			return AuthorizationTokenKind.AUTHORIZATION_CODE;
		}
		if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return AuthorizationTokenKind.ACCESS_TOKEN;
		}
		if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return AuthorizationTokenKind.REFRESH_TOKEN;
		}
		if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
			return AuthorizationTokenKind.ID_TOKEN;
		}
		return null;
	}

	private static OAuth2AuthenticationException concurrentUpdate() {
		return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
	}

	private static UUID parseOptionalUuid(String value) {
		try {
			return value == null ? null : UUID.fromString(value);
		}
		catch (IllegalArgumentException exception) {
			return null;
		}
	}

	private static Instant instant(ResultSet resultSet, String column) throws SQLException {
		return resultSet.getObject(column, OffsetDateTime.class).toInstant();
	}

	private static Instant instantOrNull(ResultSet resultSet, String column) throws SQLException {
		OffsetDateTime value = resultSet.getObject(column, OffsetDateTime.class);
		return value == null ? null : value.toInstant();
	}

	private static OffsetDateTime offset(Instant value) {
		return value == null ? null : OffsetDateTime.ofInstant(value, ZoneOffset.UTC);
	}

	private record DesiredToken(String value, Instant issuedAt, Instant expiresAt, boolean invalidated,
			String accessTokenType, Set<String> scopes, Map<String, Object> claims) {

		private DesiredToken {
			scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
			claims = claims == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
		}

	}

	private record StoredAuthorization(UUID authorizationId, UUID tenantId, UUID clientId, UUID userId,
			UUID sessionId, String clientIdentifier, String principalName, AuthorizationGrantKind grantType,
			String authorizationUri, String redirectUri, String clientState, short requestVersion, String requestParameters, long version, Instant createdAt,
			Instant updatedAt, Instant purgeAt, String authenticationMethod, Instant authenticatedAt) {
	}

	private record StoredToken(UUID tokenId, AuthorizationTokenKind kind, byte[] digest, String keyId,
			byte[] initializationVector, byte[] ciphertext, String accessTokenType, String claimsJson,
			Set<String> scopes, Map<String, Object> claims, Instant issuedAt, Instant expiresAt, boolean invalidated,
			long version) {

		private StoredToken {
			digest = digest.clone();
			initializationVector = initializationVector.clone();
			ciphertext = ciphertext.clone();
			scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
			claims = claims == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(claims));
		}

		private StoredToken withPayload(Set<String> tokenScopes, Map<String, Object> tokenClaims) {
			return new StoredToken(this.tokenId, this.kind, this.digest, this.keyId, this.initializationVector,
					this.ciphertext, this.accessTokenType, this.claimsJson, tokenScopes, tokenClaims, this.issuedAt,
					this.expiresAt, this.invalidated, this.version);
		}

		@Override
		public byte[] digest() {
			return this.digest.clone();
		}

		@Override
		public byte[] initializationVector() {
			return this.initializationVector.clone();
		}

		@Override
		public byte[] ciphertext() {
			return this.ciphertext.clone();
		}

	}

}
