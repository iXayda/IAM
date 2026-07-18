package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
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
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

class JdbcOAuth2AuthorizationServiceIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID USER_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a1001");

	private static final UUID SESSION_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a1002");

	private static final UUID CLIENT_ID = UUID.fromString("019cc877-a938-727f-8ba6-7ce0153a1003");

	private static final String CLIENT_IDENTIFIER = "authorization-service-client";

	private static final String REDIRECT_URI = "https://client.example.test/callback";

	private static final String CODE_CHALLENGE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

	private static final Instant AUTHENTICATED_AT =
			Instant.now().truncatedTo(ChronoUnit.MICROS).minusSeconds(60);

	@Autowired
	private JdbcOAuth2AuthorizationService authorizations;

	@Autowired
	private JdbcClient jdbcClient;

	@BeforeEach
	void createFixtures() {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID)
			.update();
		this.jdbcClient.sql("""
				INSERT INTO user_sessions
				    (tenant_id, session_id, user_id, authentication_method, status,
				     issued_tenant_version, issued_user_version, authenticated_at, updated_at, expires_at)
				VALUES
				    (:tenantId, :sessionId, :userId, 'password', 'active', 0, 0,
				     :authenticatedAt, :authenticatedAt, :expiresAt)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("sessionId", SESSION_ID)
			.param("userId", USER_ID)
			.param("authenticatedAt", offset(AUTHENTICATED_AT))
			.param("expiresAt", offset(Instant.now().plus(Duration.ofHours(8))))
			.update();
		this.jdbcClient.sql("""
				INSERT INTO oauth_clients
				    (client_id, tenant_id, client_identifier, display_name, client_type, authentication_method)
				VALUES (:clientId, :tenantId, :identifier, 'Authorization Service Client', 'public', 'none')
				""")
			.param("clientId", CLIENT_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("identifier", CLIENT_IDENTIFIER)
			.update();
		this.jdbcClient.sql("""
				INSERT INTO oauth_client_redirect_uris (tenant_id, client_id, redirect_uri)
				VALUES (:tenantId, :clientId, :redirectUri)
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("clientId", CLIENT_ID)
			.param("redirectUri", REDIRECT_URI)
			.update();
		for (String scope : List.of("openid", "api.read")) {
			this.jdbcClient.sql("""
					INSERT INTO oauth_client_scopes (tenant_id, client_id, scope)
					VALUES (:tenantId, :clientId, :scope)
					""")
				.param("tenantId", TenantId.DEFAULT.value())
				.param("clientId", CLIENT_ID)
				.param("scope", scope)
				.update();
		}
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM oauth_authorizations WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM oauth_authorization_consents WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE session_id = :sessionId")
			.param("sessionId", SESSION_ID)
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update();
	}

	@Test
	void roundTripsAndRotatesTheOfficialTokenLifecycle() throws Exception {
		UUID authorizationId = UUID.randomUUID();
		OAuth2Authorization pending = pendingAuthorization(authorizationId, "consent-state");

		this.authorizations.save(pending);

		OAuth2Authorization storedPending = this.authorizations.findByToken("consent-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		assertThat(storedPending).isNotNull();
		assertThat(storedPending.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isZero();
		assertPrincipalAndRequest(storedPending);
		assertProtected("consent-state", "state");

		Instant codeIssuedAt = Instant.now();
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("authorization-code", codeIssuedAt,
				codeIssuedAt.plusSeconds(300));
		OAuth2Authorization withCode = OAuth2Authorization.from(storedPending)
			.authorizedScopes(Set.of("openid", "api.read"))
			.token(code)
			.attributes(attributes -> attributes.remove(OAuth2ParameterNames.STATE))
			.build();
		this.authorizations.save(withCode);

		assertThat(this.authorizations.findByToken("consent-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE))).isNull();
		OAuth2Authorization storedCode = this.authorizations.findByToken("authorization-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(storedCode).isNotNull();
		assertThat(storedCode.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isOne();
		assertThat(storedCode.getToken(OAuth2AuthorizationCode.class).isActive()).isTrue();
		Instant scopesGrantedAt = scopesGrantedAt(authorizationId);
		this.authorizations.remove(storedPending);
		assertThat(this.authorizations.findById(authorizationId.toString())).isNotNull();

		Instant tokenIssuedAt = AuthorizationTime.toDatabasePrecision(Instant.now());
		Map<String, Object> accessClaims = Map.of("sub", USER_ID.toString(), "iat", tokenIssuedAt);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				tokenIssuedAt, tokenIssuedAt.plusSeconds(600), Set.of("openid", "api.read"));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", tokenIssuedAt,
				tokenIssuedAt.plusSeconds(3600));
		Map<String, Object> idClaims = Map.of("sub", USER_ID.toString(), "aud", List.of(CLIENT_IDENTIFIER),
				"iat", tokenIssuedAt, "exp", tokenIssuedAt.plusSeconds(600), "nonce", "oidc-nonce", "sid",
				SESSION_ID.toString(), "auth_time", Date.from(AUTHENTICATED_AT));
		OidcIdToken idToken = new OidcIdToken("id-token", tokenIssuedAt, tokenIssuedAt.plusSeconds(600), idClaims);
		OAuth2AuthorizationCode persistedCode = storedCode.getToken(OAuth2AuthorizationCode.class).getToken();
		OAuth2Authorization completed = OAuth2Authorization.from(storedCode)
			.token(accessToken, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, accessClaims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.refreshToken(refreshToken)
			.token(idToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idClaims))
			.invalidate(persistedCode)
			.build();
		this.authorizations.save(completed);

		OAuth2Authorization stored = this.authorizations.findByToken("authorization-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(stored).isNotNull();
		assertThat(stored.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isEqualTo(2);
		assertThat(stored.getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(stored.getAccessToken().getToken()).isEqualTo(accessToken);
		assertThat(stored.getAccessToken().getClaims()).isEqualTo(accessClaims);
		assertThat(stored.getAccessToken().<String>getMetadata(OAuth2TokenFormat.class.getName()))
			.isEqualTo(OAuth2TokenFormat.SELF_CONTAINED.getValue());
		assertThat(stored.getRefreshToken().getToken()).isEqualTo(refreshToken);
		assertThat(stored.getToken(OidcIdToken.class).getToken().getClaims()).isEqualTo(idClaims);
		assertThat(this.authorizations.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN)).isEqualTo(stored);
		assertThat(this.authorizations.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN)).isEqualTo(stored);
		assertThat(this.authorizations.findByToken("id-token",
				new OAuth2TokenType(OidcParameterNames.ID_TOKEN))).isEqualTo(stored);
		assertThat(this.authorizations.findByToken("access-token", null)).isEqualTo(stored);
		assertThat(this.authorizations.findById(authorizationId.toString())).isEqualTo(stored);
		assertProtected("authorization-code", "authorization_code");
		assertProtected("access-token", "access_token");
		assertProtected("refresh-token", "refresh_token");
		assertProtected("id-token", "id_token");

		OAuth2Authorization staleBeforeRotation = this.authorizations.findByToken("refresh-token",
				OAuth2TokenType.REFRESH_TOKEN);
		Instant rotatedAt = AuthorizationTime.toDatabasePrecision(Instant.now());
		OAuth2AccessToken uncoordinatedAccess = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"uncoordinated-access-token", rotatedAt, rotatedAt.plusSeconds(600), Set.of("openid"));
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(stored)
			.token(uncoordinatedAccess, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
						Map.of("sub", USER_ID.toString(), "iat", rotatedAt));
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.build()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Persisted authorization token payload is immutable");
		assertThat(this.authorizations.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN)).isNotNull();

		OAuth2Authorization firstRotation = rotate(stored, "first-rotated", rotatedAt);
		OAuth2Authorization secondRotation = rotate(staleBeforeRotation, "second-rotated", rotatedAt);
		CountDownLatch rotationStart = new CountDownLatch(1);
		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Boolean> firstResult = executor.submit(() -> rotate(firstRotation, rotationStart));
			Future<Boolean> secondResult = executor.submit(() -> rotate(secondRotation, rotationStart));
			rotationStart.countDown();

			assertThat(List.of(firstResult.get(), secondResult.get())).containsExactlyInAnyOrder(true, false);
		}

		assertThat(this.authorizations.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN)).isNull();
		assertThat(this.authorizations.findByToken("refresh-token", OAuth2TokenType.REFRESH_TOKEN)).isNull();
		assertThat(this.authorizations.findByToken("id-token",
				new OAuth2TokenType(OidcParameterNames.ID_TOKEN))).isNull();
		OAuth2Authorization storedRotation = this.authorizations.findByToken("first-rotated-refresh-token",
				OAuth2TokenType.REFRESH_TOKEN);
		String rotationPrefix = "first-rotated";
		if (storedRotation == null) {
			storedRotation = this.authorizations.findByToken("second-rotated-refresh-token",
					OAuth2TokenType.REFRESH_TOKEN);
			rotationPrefix = "second-rotated";
		}
		assertThat(storedRotation.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isEqualTo(3);
		assertThat(storedRotation.getAccessToken().getToken().getScopes()).containsExactly("openid");
		assertThat(storedRotation.getRefreshToken().getToken().getTokenValue())
			.isEqualTo(rotationPrefix + "-refresh-token");
		assertThat(storedRotation.getToken(OidcIdToken.class).getToken().getTokenValue())
			.isEqualTo(rotationPrefix + "-id-token");
		assertThat(tokenCount(authorizationId, "access_token")).isOne();
		assertThat(tokenCount(authorizationId, "refresh_token")).isOne();
		assertThat(tokenCount(authorizationId, "id_token")).isOne();
		assertProtected(rotationPrefix + "-refresh-token", "refresh_token");

		OAuth2RefreshToken persistedRefreshToken = storedRotation.getRefreshToken().getToken();
		this.authorizations
			.save(OAuth2Authorization.from(storedRotation).invalidate(persistedRefreshToken).build());
		OAuth2Authorization replayed = this.authorizations.findByToken("authorization-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(replayed.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isEqualTo(4);
		assertThat(replayed.getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(replayed.getAccessToken().isInvalidated()).isTrue();
		assertThat(replayed.getRefreshToken().isInvalidated()).isTrue();
		assertThat(scopesGrantedAt(authorizationId)).isEqualTo(scopesGrantedAt);

		this.authorizations.remove(replayed);
		assertThat(this.authorizations.findById(authorizationId.toString())).isNull();
	}

	@Test
	void roundTripsTheOfficialClientCredentialsAuthorization() {
		configureClientCredentialsGrant();
		UUID authorizationId = UUID.randomUUID();
		OAuth2Authorization issued = clientCredentialsAuthorization(authorizationId, "service-access-token");

		this.authorizations.save(issued);

		OAuth2Authorization stored = this.authorizations.findByToken("service-access-token",
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(stored).isNotNull();
		assertThat(stored.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(stored.getPrincipalName()).isEqualTo(CLIENT_IDENTIFIER);
		assertThat(stored.getAuthorizedScopes()).containsExactly("api.read");
		assertThat(stored.getAccessToken().getClaims()).containsEntry("sub", CLIENT_IDENTIFIER);
		assertThat(stored.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isZero();
		assertThat(stored.<Object>getAttribute(Principal.class.getName())).isNull();
		assertThat(stored.<Object>getAttribute(OAuth2AuthorizationRequest.class.getName())).isNull();
		assertThat(stored.getRefreshToken()).isNull();
		assertThat(stored.getToken(OAuth2AuthorizationCode.class)).isNull();
		assertThat(stored.getToken(OidcIdToken.class)).isNull();
		assertThat(this.authorizations.findById(authorizationId.toString())).isEqualTo(stored);
		assertThat(this.authorizations.findByToken("service-access-token", null)).isEqualTo(stored);
		assertProtected("service-access-token", "access_token");
		assertThat(this.jdbcClient.sql("""
				SELECT user_id IS NULL AND session_id IS NULL AND authorization_uri IS NULL
				       AND redirect_uri IS NULL AND client_state IS NULL
				       AND request_parameters = '{}'::jsonb
				       AND authorization_grant_type = 'client_credentials'
				FROM oauth_authorizations
				WHERE authorization_id = :authorizationId
				""")
			.param("authorizationId", authorizationId)
			.query(Boolean.class)
			.single()).isTrue();

		this.authorizations.save(stored);
		OAuth2Authorization resaved = this.authorizations.findById(authorizationId.toString());
		assertThat(resaved.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isOne();
		assertThat(resaved.getAccessToken().getToken()).isEqualTo(stored.getAccessToken().getToken());
		assertThat(resaved.getAccessToken().getClaims()).isEqualTo(stored.getAccessToken().getClaims());

		OAuth2AccessToken persistedAccessToken = resaved.getAccessToken().getToken();
		this.authorizations.save(OAuth2Authorization.from(resaved).invalidate(persistedAccessToken).build());
		OAuth2Authorization invalidated = this.authorizations.findById(authorizationId.toString());
		assertThat(invalidated.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isEqualTo(2);
		assertThat(invalidated.getAccessToken().isInvalidated()).isTrue();

		this.authorizations.remove(invalidated);
		assertThat(this.authorizations.findById(authorizationId.toString())).isNull();
		assertThat(this.authorizations.findByToken("service-access-token", OAuth2TokenType.ACCESS_TOKEN)).isNull();
	}

	@Test
	void rejectsClientCredentialsWritesForMismatchedOrInactiveOwners() {
		OAuth2Authorization mismatched = clientCredentialsAuthorization(UUID.randomUUID(), "mismatched-token");
		assertThatThrownBy(() -> this.authorizations.save(mismatched))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception).getError().getErrorCode())
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

		configureClientCredentialsGrant();
		this.jdbcClient.sql("UPDATE oauth_clients SET status = 'disabled' WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();
		OAuth2Authorization inactive = clientCredentialsAuthorization(UUID.randomUUID(), "inactive-token");
		assertThatThrownBy(() -> this.authorizations.save(inactive))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception).getError().getErrorCode())
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
	}

	@Test
	void allowsOnlyOneConcurrentCodeExchangeToCommit() throws Exception {
		UUID authorizationId = UUID.randomUUID();
		Instant codeIssuedAt = Instant.now();
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("concurrent-code", codeIssuedAt,
				codeIssuedAt.plusSeconds(300));
		this.authorizations.save(authorizationWithCode(authorizationId, code));
		OAuth2Authorization first = this.authorizations.findByToken("concurrent-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		OAuth2Authorization second = this.authorizations.findByToken("concurrent-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		CountDownLatch start = new CountDownLatch(1);

		try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
			Future<Boolean> firstResult = executor.submit(() -> exchange(first, "concurrent-access-1", start));
			Future<Boolean> secondResult = executor.submit(() -> exchange(second, "concurrent-access-2", start));
			start.countDown();

			assertThat(List.of(firstResult.get(), secondResult.get())).containsExactlyInAnyOrder(true, false);
		}

		OAuth2Authorization stored = this.authorizations.findByToken("concurrent-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(stored.getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(stored.getAccessToken().getToken().getTokenValue())
			.isIn("concurrent-access-1", "concurrent-access-2");
		assertThat(tokenCount(authorizationId, "access_token")).isOne();
	}

	@Test
	void coordinatesApprovalAndDenialWithoutReportingOrResurrectingStaleState() {
		UUID approvalWinnerId = UUID.randomUUID();
		this.authorizations.save(pendingAuthorization(approvalWinnerId, "approval-winner-state"));
		OAuth2Authorization staleDenial = this.authorizations.findByToken("approval-winner-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		OAuth2Authorization approval = this.authorizations.findByToken("approval-winner-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		this.authorizations.save(approve(approval, "approval-winner-code"));

		assertThat(this.authorizations.removeIfCurrent(staleDenial)).isFalse();
		assertThat(this.authorizations.findByToken("approval-winner-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE))).isNotNull();

		UUID denialWinnerId = UUID.randomUUID();
		this.authorizations.save(pendingAuthorization(denialWinnerId, "denial-winner-state"));
		OAuth2Authorization denial = this.authorizations.findByToken("denial-winner-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		OAuth2Authorization staleApproval = this.authorizations.findByToken("denial-winner-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));

		assertThat(this.authorizations.removeIfCurrent(denial)).isTrue();
		assertThatThrownBy(() -> this.authorizations.save(approve(staleApproval, "denial-winner-code")))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception).getError().getErrorCode())
				.isEqualTo("invalid_grant"));
		assertThat(this.authorizations.findById(denialWinnerId.toString())).isNull();
	}

	@Test
	void resavesPendingAuthorizationWithoutExtendingItsLifetime() {
		UUID authorizationId = UUID.randomUUID();
		this.authorizations.save(pendingAuthorization(authorizationId, "idempotent-state"));
		OAuth2Authorization stored = this.authorizations.findByToken("idempotent-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		Instant expiresAt = tokenExpiresAt(authorizationId, "state");

		this.authorizations.save(stored);

		OAuth2Authorization reloaded = this.authorizations.findByToken("idempotent-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));
		assertThat(reloaded.<Long>getAttribute(AuthorizationSnapshotMapper.REVISION_ATTRIBUTE)).isOne();
		assertThat(tokenExpiresAt(authorizationId, "state")).isEqualTo(expiresAt);
		this.authorizations.remove(reloaded);
	}

	@Test
	void acceptsProfileRevisionsAndRejectsSecurityRevisions() {
		UUID authorizationId = UUID.randomUUID();
		this.authorizations.save(pendingAuthorization(authorizationId, "profile-revision-state"));
		OAuth2Authorization pending = this.authorizations.findByToken("profile-revision-state",
				new OAuth2TokenType(OAuth2ParameterNames.STATE));

		this.jdbcClient.sql("""
				UPDATE users
				SET display_name = 'Alice Example', version = 1
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID)
			.update();
		this.authorizations.save(approve(pending, "profile-revision-code"));
		OAuth2Authorization approved = this.authorizations.findByToken("profile-revision-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(approved).isNotNull();

		this.jdbcClient.sql("""
				UPDATE users
				SET version = 2, security_version = 1
				WHERE tenant_id = :tenantId AND user_id = :userId
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID)
			.update();
		OAuth2AuthorizationCode code = approved.getToken(OAuth2AuthorizationCode.class).getToken();
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(approved).invalidate(code).build()))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception).getError().getErrorCode())
				.isEqualTo("invalid_grant"));
	}

	@Test
	void roundTripsNanosecondTokenTimesAtDatabasePrecision() {
		UUID authorizationId = UUID.randomUUID();
		Instant issuedAt = Instant.now().minusSeconds(60).with(ChronoField.NANO_OF_SECOND, 123_456_789);
		Instant expiresAt = issuedAt.plusSeconds(300).plusNanos(222);
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode("nanosecond-code", issuedAt, expiresAt);
		this.authorizations.save(authorizationWithCode(authorizationId, code));

		OAuth2Authorization stored = this.authorizations.findByToken("nanosecond-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		OAuth2AuthorizationCode storedCode = stored.getToken(OAuth2AuthorizationCode.class).getToken();
		assertThat(storedCode.getIssuedAt()).isEqualTo(AuthorizationTime.toDatabasePrecision(issuedAt));
		assertThat(storedCode.getExpiresAt()).isEqualTo(AuthorizationTime.toDatabasePrecision(expiresAt));

		this.authorizations.save(OAuth2Authorization.from(stored).invalidate(storedCode).build());
		OAuth2Authorization invalidated = this.authorizations.findByToken("nanosecond-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));
		assertThat(invalidated.getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		this.authorizations.remove(invalidated);
	}

	@Test
	void readsHistoricalAndExpiredTokensButRejectsWritesForInactiveOwners() {
		UUID authorizationId = UUID.randomUUID();
		Instant issuedAt = Instant.now().minusSeconds(600);
		OAuth2AuthorizationCode expiredCode = new OAuth2AuthorizationCode("expired-code", issuedAt,
				issuedAt.plusSeconds(60));
		this.authorizations.save(authorizationWithCode(authorizationId, expiredCode));
		this.jdbcClient.sql("UPDATE oauth_clients SET status = 'disabled' WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();

		OAuth2Authorization stored = this.authorizations.findByToken("expired-code",
				new OAuth2TokenType(OAuth2ParameterNames.CODE));

		assertThat(stored).isNotNull();
		assertThat(stored.getToken(OAuth2AuthorizationCode.class).isExpired()).isTrue();
		OAuth2AuthorizationCode persistedCode = stored.getToken(OAuth2AuthorizationCode.class).getToken();
		OAuth2Authorization changed = OAuth2Authorization.from(stored).invalidate(persistedCode).build();
		assertThatThrownBy(() -> this.authorizations.save(changed))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.satisfies(exception -> assertThat(((OAuth2AuthenticationException) exception).getError().getErrorCode())
				.isEqualTo("invalid_grant"));
	}

	@Test
	void rejectsUnsupportedAggregateStateAndMalformedLookups() {
		OAuth2Authorization unsupported = OAuth2Authorization.from(pendingAuthorization(UUID.randomUUID(), "state"))
			.attribute("unsupported", "value")
			.build();

		assertThatThrownBy(() -> this.authorizations.save(unsupported))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Authorization contains unsupported attributes");
		assertThat(this.authorizations.findById("not-a-uuid")).isNull();
		assertThat(this.authorizations.findById(null)).isNull();
		assertThat(this.authorizations.findByToken("missing", OAuth2TokenType.REFRESH_TOKEN)).isNull();
		assertThatThrownBy(() -> this.authorizations.findByToken("", null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Token must contain 1 to 24576 characters");
		assertThatThrownBy(() -> this.authorizations.findByToken("x".repeat(24_577), null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("Token must contain 1 to 24576 characters");
	}

	private boolean exchange(OAuth2Authorization authorization, String tokenValue,
			CountDownLatch start) throws InterruptedException {
		start.await();
		Instant issuedAt = Instant.now();
		Map<String, Object> claims = Map.of("sub", USER_ID.toString(), "iat", issuedAt);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue,
				issuedAt, issuedAt.plusSeconds(600), Set.of("openid", "api.read"));
		OAuth2Authorization exchanged = OAuth2Authorization.from(authorization)
			.token(accessToken, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.invalidate(authorization.getToken(OAuth2AuthorizationCode.class).getToken())
			.build();
		try {
			this.authorizations.save(exchanged);
			return true;
		}
		catch (OAuth2AuthenticationException exception) {
			assertThat(exception.getError().getErrorCode()).isEqualTo("invalid_grant");
			return false;
		}
	}

	private boolean rotate(OAuth2Authorization authorization, CountDownLatch start) throws InterruptedException {
		start.await();
		try {
			this.authorizations.save(authorization);
			return true;
		}
		catch (OAuth2AuthenticationException exception) {
			assertThat(exception.getError().getErrorCode()).isEqualTo("invalid_grant");
			return false;
		}
	}

	private OAuth2Authorization pendingAuthorization(UUID authorizationId, String state) {
		return baseAuthorization(authorizationId)
			.attribute(OAuth2ParameterNames.STATE, state)
			.build();
	}

	private OAuth2Authorization authorizationWithCode(UUID authorizationId, OAuth2AuthorizationCode code) {
		return baseAuthorization(authorizationId)
			.authorizedScopes(Set.of("openid", "api.read"))
			.token(code)
			.build();
	}

	private OAuth2Authorization clientCredentialsAuthorization(UUID authorizationId, String tokenValue) {
		Instant issuedAt = AuthorizationTime.toDatabasePrecision(Instant.now());
		Map<String, Object> claims = Map.of("sub", CLIENT_IDENTIFIER, "iat", issuedAt,
				"tenant_id", TenantId.DEFAULT.value().toString());
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue,
				issuedAt, issuedAt.plusSeconds(300), Set.of("api.read"));
		return OAuth2Authorization.withRegisteredClient(serviceRegisteredClient())
			.id(authorizationId.toString())
			.principalName(CLIENT_IDENTIFIER)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.authorizedScopes(Set.of("api.read"))
			.token(accessToken, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.build();
	}

	private void configureClientCredentialsGrant() {
		this.jdbcClient.sql("DELETE FROM oauth_client_redirect_uris WHERE client_id = :clientId")
			.param("clientId", CLIENT_ID)
			.update();
		this.jdbcClient.sql("""
				UPDATE oauth_clients
				SET client_type = 'confidential',
				    authentication_method = 'client_secret_basic',
				    encoded_client_secret = '{test}abcdefghijklmnopqrstuvwxyz0123456789',
				    client_secret_issued_at = created_at,
				    client_secret_expires_at = created_at + interval '1 day',
				    authorization_grant_type = 'client_credentials'
				WHERE client_id = :clientId
				""")
			.param("clientId", CLIENT_ID)
			.update();
	}

	private static OAuth2Authorization approve(OAuth2Authorization pending, String codeValue) {
		Instant issuedAt = Instant.now();
		OAuth2AuthorizationCode code = new OAuth2AuthorizationCode(codeValue, issuedAt, issuedAt.plusSeconds(300));
		return OAuth2Authorization.from(pending)
			.authorizedScopes(Set.of("openid", "api.read"))
			.token(code)
			.attributes(attributes -> attributes.remove(OAuth2ParameterNames.STATE))
			.build();
	}

	private static OAuth2Authorization rotate(OAuth2Authorization current, String prefix, Instant issuedAt) {
		Map<String, Object> accessClaims = Map.of("sub", USER_ID.toString(), "iat", issuedAt);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				prefix + "-access-token", issuedAt, issuedAt.plusSeconds(600), Set.of("openid"));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(prefix + "-refresh-token", issuedAt,
				issuedAt.plusSeconds(3600));
		Map<String, Object> idClaims = Map.of("sub", USER_ID.toString(), "aud", List.of(CLIENT_IDENTIFIER),
				"iat", issuedAt, "exp", issuedAt.plusSeconds(600), "sid", SESSION_ID.toString(), "auth_time",
				Date.from(AUTHENTICATED_AT));
		OidcIdToken idToken = new OidcIdToken(prefix + "-id-token", issuedAt, issuedAt.plusSeconds(600), idClaims);
		return OAuth2Authorization.from(current)
			.token(accessToken, metadata -> {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, accessClaims);
				metadata.put(OAuth2TokenFormat.class.getName(), OAuth2TokenFormat.SELF_CONTAINED.getValue());
			})
			.refreshToken(refreshToken)
			.token(idToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idClaims))
			.build();
	}

	private OAuth2Authorization.Builder baseAuthorization(UUID authorizationId) {
		AuthorizationPrincipal principal = new AuthorizationPrincipal(TenantId.DEFAULT, new UserId(USER_ID),
				new SessionId(SESSION_ID), SessionAuthenticationMethod.PASSWORD, AUTHENTICATED_AT);
		AuthorizationUserAuthentication authentication = AuthorizationUserAuthentication.authenticated(principal,
				List.of(new SimpleGrantedAuthority("ROLE_USER"), FactorGrantedAuthority
					.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
					.issuedAt(principal.authenticatedAt())
					.build()));
		return OAuth2Authorization.withRegisteredClient(registeredClient())
			.id(authorizationId.toString())
			.principalName(USER_ID.toString())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.attribute(Principal.class.getName(), authentication)
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest());
	}

	private static RegisteredClient registeredClient() {
		return RegisteredClient.withId(CLIENT_ID.toString())
			.clientId(CLIENT_IDENTIFIER)
			.clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(REDIRECT_URI)
			.scope("openid")
			.scope("api.read")
			.build();
	}

	private static RegisteredClient serviceRegisteredClient() {
		return RegisteredClient.withId(CLIENT_ID.toString())
			.clientId(CLIENT_IDENTIFIER)
			.clientAuthenticationMethod(
					org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.scope("api.read")
			.build();
	}

	private static OAuth2AuthorizationRequest authorizationRequest() {
		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("https://issuer.example.test/oauth2/authorize")
			.clientId(CLIENT_IDENTIFIER)
			.redirectUri(REDIRECT_URI)
			.scopes(Set.of("openid", "api.read"))
			.state("client-state")
			.additionalParameters(Map.of("code_challenge", CODE_CHALLENGE,
					"code_challenge_method", "S256", "nonce", "oidc-nonce"))
			.build();
	}

	private static void assertPrincipalAndRequest(OAuth2Authorization authorization) {
		AuthorizationUserAuthentication authentication = authorization.getAttribute(Principal.class.getName());
		assertThat(authentication.getPrincipal().tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(authentication.getPrincipal().userId()).isEqualTo(new UserId(USER_ID));
		assertThat(authentication.getPrincipal().sessionId()).isEqualTo(new SessionId(SESSION_ID));
		assertThat(authentication.getCredentials()).isNull();
		FactorGrantedAuthority factor = authentication.getAuthorities()
			.stream()
			.filter(FactorGrantedAuthority.class::isInstance)
			.map(FactorGrantedAuthority.class::cast)
			.findFirst()
			.orElseThrow();
		assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
		assertThat(factor.getIssuedAt()).isEqualTo(AUTHENTICATED_AT);
		OAuth2AuthorizationRequest request = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationRequest expected = authorizationRequest();
		assertThat(request.getAuthorizationUri()).isEqualTo(expected.getAuthorizationUri());
		assertThat(request.getGrantType()).isEqualTo(expected.getGrantType());
		assertThat(request.getResponseType()).isEqualTo(expected.getResponseType());
		assertThat(request.getClientId()).isEqualTo(expected.getClientId());
		assertThat(request.getRedirectUri()).isEqualTo(expected.getRedirectUri());
		assertThat(request.getScopes()).isEqualTo(expected.getScopes());
		assertThat(request.getState()).isEqualTo(expected.getState());
		assertThat(request.getAdditionalParameters()).isEqualTo(expected.getAdditionalParameters());
		assertThat(request.getAttributes()).isEmpty();
	}

	private void assertProtected(String rawValue, String tokenType) {
		StoredProtection protection = this.jdbcClient.sql("""
				SELECT token_digest, initialization_vector, ciphertext
				FROM oauth_authorization_tokens
				WHERE token_type = :tokenType AND authorization_id IN (
				    SELECT authorization_id FROM oauth_authorizations WHERE client_id = :clientId
				)
				""")
			.param("tokenType", tokenType)
			.param("clientId", CLIENT_ID)
			.query((resultSet, rowNumber) -> new StoredProtection(resultSet.getBytes("token_digest"),
					resultSet.getBytes("initialization_vector"), resultSet.getBytes("ciphertext")))
			.single();
		assertThat(protection.digest()).hasSize(32);
		assertThat(protection.initializationVector()).hasSize(12);
		assertThat(new String(protection.ciphertext(), StandardCharsets.ISO_8859_1)).doesNotContain(rawValue);
	}

	private int tokenCount(UUID authorizationId, String tokenType) {
		return this.jdbcClient.sql("""
				SELECT count(*)
				FROM oauth_authorization_tokens
				WHERE authorization_id = :authorizationId AND token_type = :tokenType
				""")
			.param("authorizationId", authorizationId)
			.param("tokenType", tokenType)
			.query(Integer.class)
			.single();
	}

	private Instant tokenExpiresAt(UUID authorizationId, String tokenType) {
		return this.jdbcClient.sql("""
				SELECT expires_at
				FROM oauth_authorization_tokens
				WHERE authorization_id = :authorizationId AND token_type = :tokenType
				""")
			.param("authorizationId", authorizationId)
			.param("tokenType", tokenType)
			.query(OffsetDateTime.class)
			.single()
			.toInstant();
	}

	private Instant scopesGrantedAt(UUID authorizationId) {
		return this.jdbcClient.sql("""
				SELECT min(granted_at)
				FROM oauth_authorization_scopes
				WHERE authorization_id = :authorizationId
				""")
			.param("authorizationId", authorizationId)
			.query(OffsetDateTime.class)
			.single()
			.toInstant();
	}

	private static OffsetDateTime offset(Instant value) {
		return OffsetDateTime.ofInstant(value, ZoneOffset.UTC);
	}

	private record StoredProtection(byte[] digest, byte[] initializationVector, byte[] ciphertext) {
	}

}
