package com.ixayda.iam.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityApplicationRoles;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityRefreshTokens;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.IdentityUserRoles;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.SecurityAudits;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthorizationCodeProviderIntegrationTests {

	private static final Path SIGNING_KEY = keyFile(32);
	private static final Path AUTHORIZATION_KEY = keyFile(64);
	private static final String PASSWORD = "saffron village ripple lantern 936";
	private static final String REDIRECT = "https://orders.example/callback";
	private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private static final String NONCE = "oidc-code-exchange-nonce";
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:exchange-test", "internal:exchange", UUID.randomUUID());
	@Autowired private IdentityApplicationRoles applications;
	@Autowired private IdentityAuthorizationSessions sessions;
	@Autowired private IdentityAuthorizations authorizations;
	@Autowired private IdentityAuthorizationBindings bindings;
	@Autowired private IdentityProtocolClients protocol;
	@Autowired private IdentityRefreshTokens refresh;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUserRoles assignments;
	@Autowired private IdentitySigningKeys keys;
	@Autowired private SecurityAudits audits;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private ApplicationContext context;
	private IdentityAuthorizationCodeProvider provider;
	private IdentityAuthorizationRequestProvider requests;
	private SessionRepository<Session> store;
	private IdentitySigningKey signing;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;
	private UUID clientId;
	private String secret;
	private String sessionId;
	private long authenticatedAt;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("iam.signing.key-file", SIGNING_KEY::toString); registry.add("iam.authorization.key-file", AUTHORIZATION_KEY::toString);
	}

	@BeforeEach
	@SuppressWarnings("unchecked")
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_browser_session,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.keys.initialize(); this.signing = this.keys.findPublicKey().orElseThrow(); this.userId = activeUser("alice");
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
		this.assignments.change(this.userId, this.roleId, 0, true, AUDIT);
		var created = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		this.clientId = created.client().id(); this.secret = created.secret();
		var official = new JdbcIndexedSessionRepository(this.template, new TransactionTemplate(this.transactions));
		official.setTableName("iam_browser_session"); official.setDefaultMaxInactiveInterval(Duration.ofMinutes(30));
		this.store = (SessionRepository<Session>) (SessionRepository<?>) official;
		this.authenticatedAt = System.currentTimeMillis() - 2000;
		this.sessionId = browserSession(this.userId, this.authenticatedAt);
		this.requests = new IdentityAuthorizationRequestProvider(this.protocol, this.sessions, this.bindings, this.audits, this.transactions);
		this.provider = new IdentityAuthorizationCodeProvider(this.applications, this.sessions, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		serverContext("https://iam.example");
	}

	@AfterEach
	void removeFaultsAndReferences() {
		AuthorizationServerContextHolder.resetContext();
		for (String table : List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index", "iam_security_audit", "iam_refresh_family", "iam_refresh_history")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS exchange_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS exchange_test_fault()").update();
		this.jdbc.sql("DROP SEQUENCE IF EXISTS exchange_test_audit_probe").update();
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_browser_session CASCADE").update();
	}

	@Test
	void nativeClientProofAndExchangePersistVerifiablePurposeBoundTokensAndAuditBeforeReturning() throws Exception {
		String code = code(Set.of("openid", "profile", "offline_access"));
		var request = request(code, authenticatedClient(code));
		var result = exchange(request);
		var stored = stored(code);
		assertThat(stored.version()).isEqualTo(2);
		assertThat(stored.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(stored.authorization().getAccessToken().getToken()).isEqualTo(result.getAccessToken());
		assertThat(stored.authorization().getRefreshToken().getToken()).isEqualTo(result.getRefreshToken());
		var access = verified(result.getAccessToken().getTokenValue(), "at+jwt");
		assertThat(access.getIssuer()).isEqualTo("https://iam.example"); assertThat(access.getSubject()).isEqualTo(this.userId.toString());
		assertThat(access.getAudience()).containsExactly("urn:example:orders"); assertThat(access.getStringClaim("client_id")).isEqualTo(this.clientId.toString());
		assertThat(access.getStringClaim("authorization_id")).isEqualTo(stored.authorization().getId());
		assertThat(access.getStringClaim("scope")).isEqualTo("offline_access openid profile"); assertThat(access.getStringListClaim("roles")).containsExactly("reader");
		assertThat(Duration.between(access.getIssueTime().toInstant(), access.getExpirationTime().toInstant())).isEqualTo(Duration.ofSeconds(300));
		assertThat(access.getNotBeforeTime()).isEqualTo(access.getIssueTime()); assertThat(UUID.fromString(access.getJWTID()).toString()).isEqualTo(access.getJWTID());
		String rawId = (String) result.getAdditionalParameters().get("id_token");
		var id = verified(rawId, "JWT"); assertThat(id.getAudience()).containsExactly(this.clientId.toString());
		assertThat(id.getSubject()).isEqualTo(this.userId.toString()); assertThat(id.getStringClaim("azp")).isEqualTo(this.clientId.toString());
		assertThat(id.getStringClaim("nonce")).isEqualTo(NONCE);
		assertThat(id.getDateClaim("auth_time").toInstant()).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt).truncatedTo(ChronoUnit.SECONDS));
		assertThat(Duration.between(id.getIssueTime().toInstant(), id.getExpirationTime().toInstant())).isEqualTo(Duration.ofSeconds(300));
		assertThat(id.getJWTID()).isNotEqualTo(access.getJWTID()); assertThat(id.getClaims()).doesNotContainKeys("roles", "scope", "sid");
		assertThat(Duration.between(result.getRefreshToken().getIssuedAt(), result.getRefreshToken().getExpiresAt())).isEqualTo(Duration.ofDays(7));
		assertThat(java.util.Base64.getUrlDecoder().decode(result.getRefreshToken().getTokenValue())).hasSize(96);
		var family = this.refresh.findByAuthorization(stored.authorization()).orElseThrow();
		var history = this.refresh.findByToken(result.getRefreshToken().getTokenValue()).orElseThrow();
		assertThat(family.authorizationId().toString()).isEqualTo(stored.authorization().getId());
		assertThat(family.version()).isEqualTo(1); assertThat(family.generation()).isZero(); assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.ACTIVE);
		assertThat(family.currentDigest()).isEqualTo(history.digest()); assertThat(history.generation()).isZero(); assertThat(history.parentDigest()).isNull(); assertThat(history.consumedAt()).isNull();
		assertThat(family.scopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
		assertThat(family.startedAt()).isEqualTo(result.getRefreshToken().getIssuedAt()); assertThat(family.idleExpiresAt()).isEqualTo(result.getRefreshToken().getExpiresAt());
		assertThat(family.absoluteExpiresAt()).isEqualTo(this.bindings.findByAuthorization(stored.authorization()).orElseThrow().issuedAt().plus(30, ChronoUnit.DAYS));
		assertThat(history.digest()).isNotEqualTo(this.jdbc.sql("SELECT digest FROM iam_authorization_token_index WHERE token_type='refresh_token'").query(String.class).single());
		assertThat(this.refresh.findByToken(code)).isEmpty();
		assertThat(this.jdbc.sql("SELECT * FROM iam_refresh_history").query().singleRow().toString()).doesNotContain(result.getRefreshToken().getTokenValue(), this.secret, VERIFIER);
		assertThat(result.getPrincipal()).isInstanceOfSatisfying(OAuth2ClientAuthenticationToken.class, client -> {
			assertThat(client.getCredentials()).isNull(); assertThat(client.getDetails()).isNull();
		});
		Authentication principal = stored.authorization().getAttribute(Principal.class.getName());
		assertThat(principal.getCredentials()).isNull(); assertThat(principal.getDetails()).isNull();
		assertThat(stored.authorization().getAttributes().toString()).doesNotContain(this.secret, VERIFIER, this.sessionId, "ROLE_IAM_ADMIN", "browser-credential");
		assertThat(access.getClaims().toString() + id.getClaims()).doesNotContain(this.secret, VERIFIER, this.sessionId, "ROLE_IAM_ADMIN");
		assertThat(this.bindings.findByAuthorization(stored.authorization())).isPresent();
		var encrypted = this.jdbc.sql("SELECT * FROM oauth2_authorization").query().singleRow().toString();
		assertThat(encrypted).doesNotContain(code, result.getAccessToken().getTokenValue(), rawId, result.getRefreshToken().getTokenValue(), NONCE);
		assertThat(tokenAudits()).singleElement().satisfies(event -> {
			assertThat(event.get("action")).isEqualTo("tokens_issued"); assertThat(event.get("outcome")).isEqualTo("success");
			assertThat(event.get("target_user_id")).isEqualTo(this.userId); assertThat(event.get("actor")).isEqualTo("client:" + this.clientId);
			assertThat(event.get("correlation_id")).isEqualTo(((IdentityAuthorizationCodeProvider.RequestEvidence) request.getDetails()).correlationId());
		});
		assertThat(this.context.getBeansOfType(RegisteredClientRepository.class)).isEmpty(); assertThat(this.context.getBeansOfType(OAuth2AuthorizationService.class)).isEmpty();
		assertThat(this.context.getBeansOfType(IdentityAuthorizationCodeProvider.class)).isEmpty();
	}

	@Test
	void refreshIsNotIssuedWithoutTheActualOfflineAccessGrantEvenWhenTheRegistrationPermitsIt() throws Exception {
		String code = code(Set.of("openid", "profile"));
		var result = exchange(request(code, authenticatedClient(code)));
		assertThat(result.getRefreshToken()).isNull(); assertThat(stored(code).authorization().getRefreshToken()).isNull();
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).isEmpty();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_family").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isZero();
		assertThat(verified(result.getAccessToken().getTokenValue(), "at+jwt").getStringClaim("scope")).isEqualTo("openid profile");
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 100 })
	void accessTokenRetainsExactlyTheFullEffectiveApplicationRoleSet(int count) throws Exception {
		var allowed = new java.util.HashSet<UUID>();
		for (int index = 0; index < count; index++) {
			var role = this.roles.create(this.resourceId, "role_" + String.format(java.util.Locale.ROOT, "%03d", index), "Role " + index, AUDIT);
			allowed.add(role.id()); this.assignments.change(this.userId, role.id(), index + 1, true, AUDIT);
		}
		this.clients.updateConfiguration(this.clientId, 1, configuration(this.resourceId, allowed), AUDIT);
		String code = code(Set.of("openid")); var result = exchange(request(code, authenticatedClient(code)));
		var projected = verified(result.getAccessToken().getTokenValue(), "at+jwt").getStringListClaim("roles");
		assertThat(projected).hasSize(count).isSorted(); assertThat(projected).doesNotContain("reader", "ROLE_IAM_ADMIN");
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "empty", "short", "large", "space", "unicode", "wrong", "redirect-missing", "redirect-foreign", "duplicate", "unknown-duplicate", "resource", "audience", "scope" })
	void theGrantTransactionRechecksVerifierRedirectAndParameterShapeAfterSuccessfulClientAuthentication(String invalid) {
		String code = code(Set.of("openid", "offline_access")); var client = authenticatedClient(code);
		var parameters = new HashMap<String, Object>(); parameters.put("code_verifier", VERIFIER); String redirect = REDIRECT;
		switch (invalid) {
			case "missing" -> parameters.clear();
			case "empty" -> parameters.put("code_verifier", "");
			case "short" -> parameters.put("code_verifier", "a".repeat(42));
			case "large" -> parameters.put("code_verifier", "a".repeat(129));
			case "space" -> parameters.put("code_verifier", " " + VERIFIER);
			case "unicode" -> parameters.put("code_verifier", "\u2603" + VERIFIER);
			case "wrong" -> parameters.put("code_verifier", "x".repeat(43));
			case "redirect-missing" -> redirect = null;
			case "redirect-foreign" -> redirect = "https://attacker.example/callback";
			case "duplicate" -> parameters.put("code_verifier", new String[] { VERIFIER, VERIFIER });
			case "unknown-duplicate" -> parameters.put("unknown", new String[] { "", "" });
			default -> parameters.put(invalid, "untrusted-expansion");
		}
		rejection(new OAuth2AuthorizationCodeAuthenticationToken(code, client, redirect, parameters), Set.of("duplicate", "unknown-duplicate", "resource", "audience", "scope").contains(invalid) ? "invalid_request" : "invalid_grant");
		assertUnconsumed(code); assertThat(tokenAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("token_request_rejected"));
	}

	@Test
	void unrecognizedAndEmptyUnsupportedExtensionsCannotAlterTheBoundExchange() {
		String code = code(Set.of("openid"));
		var parameters = new HashMap<String, Object>(); parameters.put("code_verifier", VERIFIER);
		parameters.put("unknown", "ignored-extension-\u2603"); parameters.put("resource", "");
		exchange(new OAuth2AuthorizationCodeAuthenticationToken(code, authenticatedClient(code), REDIRECT, parameters));
		assertThat(stored(code).authorization().getAttributes().toString()).doesNotContain("ignored-extension");
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing-snapshot", "wrong-snapshot", "wrong-method", "credentials", "unauthenticated" })
	void onlyAnAuthenticatedBasicClientWithItsExactCapturedSnapshotCanEnterTheGrantTransaction(String invalid) {
		String code = code(Set.of("openid")); var snapshot = this.protocol.findActiveById(this.clientId.toString()).orElseThrow();
		Authentication client = new OAuth2ClientAuthenticationToken(snapshot.registration(), invalid.equals("wrong-method") ? ClientAuthenticationMethod.CLIENT_SECRET_POST : ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				invalid.equals("credentials") ? this.secret : null);
		if (invalid.equals("wrong-snapshot")) { ((OAuth2ClientAuthenticationToken) client).setDetails("untrusted-snapshot"); }
		else if (!invalid.equals("missing-snapshot")) { ((OAuth2ClientAuthenticationToken) client).setDetails(snapshot); }
		if (invalid.equals("unauthenticated")) { client = new OAuth2ClientAuthenticationToken(this.clientId.toString(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.secret, Map.of()); }
		rejection(request(code, client), "invalid_client"); assertUnconsumed(code);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-disabled", "credential", "client-secret", "client-disabled", "client-transferred", "resource", "resource-disabled", "role", "role-disabled", "assignment" })
	void currentEpochsCannotBeReplacedByTheOriginalAuthorizationOrAStaleClientProof(String mutation) {
		String code = code(Set.of("openid", "offline_access")); var client = authenticatedClient(code);
		mutate(mutation);
		rejection(request(code, client), "invalid_grant"); assertUnconsumed(code);
	}

	@ParameterizedTest
	@ValueSource(strings = { "deleted", "expired", "foreign", "authentication-time", "credential-version" })
	void anUnconsumedCodeStillRequiresTheOriginalCurrentOwnedSourceSession(String mutation) {
		String code = code(Set.of("openid")); var client = authenticatedClient(code);
		switch (mutation) {
			case "deleted" -> this.store.deleteById(this.sessionId);
			case "expired" -> this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", this.sessionId).update();
			case "foreign" -> this.jdbc.sql("UPDATE iam_browser_session SET principal_name=:user WHERE session_id=:id").param("user", activeUser("bobby").toString()).param("id", this.sessionId).update();
			case "authentication-time" -> sessionAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt + 1);
			default -> sessionAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 2L);
		}
		rejection(request(code, client), "invalid_grant"); assertUnconsumed(code);
	}

	@Test
	void cookieRotationAndAnotherDeviceCannotChangeTheBoundAuthenticationTime() throws Exception {
		String code = code(Set.of("openid"));
		var session = this.store.findById(this.sessionId); session.changeSessionId(); this.store.save(session);
		browserSession(this.userId, System.currentTimeMillis() - 10);
		var result = exchange(request(code, authenticatedClient(code)));
		assertThat(verified((String) result.getAdditionalParameters().get("id_token"), "JWT").getDateClaim("auth_time").toInstant())
				.isEqualTo(Instant.ofEpochMilli(this.authenticatedAt).truncatedTo(ChronoUnit.SECONDS));
	}

	@ParameterizedTest
	@ValueSource(strings = { "current", "deleted-source", "expired-source" })
	void aValidCodeReplayCommitsRevocationOfAllPreviouslyIssuedTokensBeforeReturningADenial(String source) {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code));
		exchange(request);
		if (source.equals("deleted-source")) { this.store.deleteById(this.sessionId); }
		if (source.equals("expired-source")) { this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", this.sessionId).update(); }
		rejection(request, "invalid_grant");
		assertRevoked(code); assertThat(stored(code).version()).isEqualTo(3);
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().satisfies(family -> {
			assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.QUARANTINED); assertThat(family.version()).isEqualTo(2); assertThat(family.generation()).isZero();
		});
		assertThat(tokenAudits()).extracting(event -> event.get("action")).containsExactly("tokens_issued", "authorization_code_replayed");
		assertThat(tokenAudits().getLast().get("outcome")).isEqualTo("failure");
	}

	@Test
	void anotherAuthenticatedClientCannotConsumeOrRevokeAnOriginalClientsCodeOrIssuedTokens() {
		String code = code(Set.of("openid", "offline_access"));
		var other = this.clients.create(configuration(this.resourceId, Set.of()), AUDIT);
		var foreign = authenticatedClient(other.client().id(), other.secret(), code);
		rejection(request(code, foreign), "invalid_grant"); assertUnconsumed(code);
		exchange(request(code, authenticatedClient(code))); var before = stored(code);
		rejection(request(code, foreign), "invalid_grant");
		assertThat(stored(code).version()).isEqualTo(before.version()); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
		assertThat(tokenAudits()).noneSatisfy(event -> assertThat(event.get("action")).isEqualTo("authorization_code_replayed"));
	}

	@Test
	void aWrongVerifierCannotUseTheReplayPathToRevokeIssuedTokens() {
		String code = code(Set.of("openid", "offline_access")); var client = authenticatedClient(code);
		exchange(request(code, client));
		rejection(new OAuth2AuthorizationCodeAuthenticationToken(code, client, REDIRECT, Map.of("code_verifier", "x".repeat(43))), "invalid_grant");
		assertThat(stored(code).version()).isEqualTo(2); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
	}

	@Test
	void anUnknownCodeCannotReuseAnAuthenticatedClientsOtherCodeProof() {
		String code = code(Set.of("openid"));
		rejection(request("unknown-authorization-code", authenticatedClient(code)), "invalid_grant"); assertUnconsumed(code);
		assertThat(tokenAudits()).singleElement().satisfies(event -> assertThat(event.get("target_user_id")).isNull());
	}

	@Test
	void anInconsistentReactivatedCodeCannotReplacePreviouslyIssuedTokens() {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code)); exchange(request);
		var current = stored(code); var source = current.authorization().getToken(OAuth2AuthorizationCode.class);
		this.authorizations.save(OAuth2Authorization.from(current.authorization()).token(source.getToken(), metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false)).build(), current.version());
		rejection(request, "server_error");
		assertThat(stored(code).version()).isEqualTo(3);
		assertThat(stored(code).authorization().getAccessToken().getToken()).isEqualTo(current.authorization().getAccessToken().getToken());
	}

	@ParameterizedTest
	@ValueSource(strings = { "native-suppressed", "native-altered", "revision-suppressed", "index-suppressed", "audit-suppressed", "deferred", "audit-unavailable", "family-suppressed", "family-altered", "history-suppressed", "history-altered", "family-deferred" })
	void partialWritesMandatoryAuditAndCommitFailuresDoNotPublishTokensOrConsumeTheCode(String failure) {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code));
		switch (failure) {
			case "native-suppressed" -> fault("oauth2_authorization", "BEFORE UPDATE", "RETURN NULL;", false);
			case "native-altered" -> fault("oauth2_authorization", "BEFORE UPDATE", "NEW.id_token_value=NULL; RETURN NEW;", false);
			case "revision-suppressed" -> fault("iam_authorization_record", "BEFORE UPDATE", "RETURN NULL;", false);
			case "index-suppressed" -> fault("iam_authorization_token_index", "BEFORE INSERT", "IF NEW.token_type='access_token' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-suppressed" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_issued' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-unavailable" -> fault("iam_security_audit", "BEFORE INSERT", "RAISE EXCEPTION 'isolated exchange audit fault';", false);
			case "family-suppressed" -> fault("iam_refresh_family", "BEFORE INSERT", "RETURN NULL;", false);
			case "family-altered" -> fault("iam_refresh_family", "BEFORE INSERT", "NEW.version=NEW.version+1; RETURN NEW;", false);
			case "history-suppressed" -> fault("iam_refresh_history", "BEFORE INSERT", "RETURN NULL;", false);
			case "history-altered" -> fault("iam_refresh_history", "BEFORE INSERT", "NEW.expires_at=NEW.expires_at-INTERVAL '1 second'; RETURN NEW;", false);
			case "family-deferred" -> fault("iam_refresh_family", "AFTER INSERT", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
			default -> fault("oauth2_authorization", "AFTER UPDATE", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
		}
		rejection(request, "server_error"); assertUnconsumed(code);
		assertThat(tokenAudits()).hasSize(failure.equals("audit-unavailable") ? 0 : 1);
	}

	@Test
	void aReplayAuditFailureRollsBackItsRevocationAndARetryCanCommitTheCompleteDecision() {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code)); exchange(request);
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_replayed' THEN RETURN NULL; END IF; RETURN NEW;", false);
		rejection(request, "server_error");
		assertThat(stored(code).version()).isEqualTo(2); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().satisfies(family -> {
			assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.ACTIVE); assertThat(family.version()).isEqualTo(1);
		});
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON iam_security_audit").update();
		rejection(request, "invalid_grant"); assertRevoked(code);
	}

	@Test
	void aSourceDeadlinePassingDuringMandatoryAuditRollsBackIssuanceAndCodeConsumption() {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code));
		this.jdbc.sql("CREATE SEQUENCE exchange_test_audit_probe").update();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_issued' THEN PERFORM nextval('exchange_test_audit_probe'); PERFORM pg_sleep(1); END IF; RETURN NEW;", false);
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", System.currentTimeMillis() + 600).param("id", this.sessionId).update();
		rejection(request, "invalid_grant"); assertUnconsumed(code);
		assertThat(this.jdbc.sql("SELECT is_called FROM exchange_test_audit_probe").query(Boolean.class).single()).isTrue();
		assertThat(tokenAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("token_request_rejected"));
	}

	@Test
	void simultaneousExchangesHaveOnlyOneSuccessfulIssuanceAndTheLosingReplayRevokesIt() throws Exception {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code)); var start = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			var first = executor.submit(() -> concurrentExchange(request, start)); var second = executor.submit(() -> concurrentExchange(request, start));
			start.countDown(); assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS))).containsExactlyInAnyOrder("success", "invalid_grant");
		}
		assertRevoked(code); assertThat(stored(code).version()).isEqualTo(3);
		assertThat(tokenAudits()).extracting(event -> event.get("action")).containsExactly("tokens_issued", "authorization_code_replayed");
	}

	@Test
	void aClientSecretChangedWhileWaitingForTheUserLockCannotUseItsPreviouslyAcceptedProof() throws Exception {
		String code = code(Set.of("openid")); var request = request(code, authenticatedClient(code));
		var locked = new CountDownLatch(1); var change = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
					locked.countDown(); awaitLatch(change); this.clients.rotateSecret(this.clientId, 1, AUDIT);
				}));
				awaitLatch(locked);
				var reader = executor.submit(() -> { serverContext("https://iam.example"); try { return rejection(request, "invalid_grant"); } finally { AuthorizationServerContextHolder.resetContext(); } });
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR SHARE%')").query(Boolean.class).single());
				change.countDown(); writer.get(10, TimeUnit.SECONDS); assertThat(reader.get(10, TimeUnit.SECONDS)).isNotNull(); assertUnconsumed(code);
			}
			finally { change.countDown(); }
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "other", "http" })
	void tokenIssuanceRequiresTheSameExplicitHttpsIssuerAsTheOriginalRequest(String invalid) {
		String code = code(Set.of("openid")); var request = request(code, authenticatedClient(code));
		if (invalid.equals("missing")) { AuthorizationServerContextHolder.resetContext(); }
		else { serverContext(invalid.equals("http") ? "http://iam.example" : "https://attacker.example"); }
		rejection(request, invalid.equals("other") ? "invalid_grant" : "server_error"); assertUnconsumed(code);
	}

	@Test
	void ambientTransactionsCannotReceiveUncommittedTokensAndNativeLocksRejectOtherIsolationLevels() {
		String code = code(Set.of("openid")); var request = request(code, authenticatedClient(code));
		assertThat(this.provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ignored", null))).isNull();
		assertThat(this.provider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
		assertThat(this.provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> rejection(request, "server_error")); assertUnconsumed(code);
		var readOnly = new TransactionTemplate(this.transactions); readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.execute(tx -> this.authorizations.lockForUse(UUID.fromString(stored(code).authorization().getId())))).isInstanceOf(IllegalStateException.class);
		var repeatable = new TransactionTemplate(this.transactions); repeatable.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		assertThatThrownBy(() -> repeatable.execute(tx -> this.authorizations.lockForUse(UUID.fromString(stored(code).authorization().getId())))).isInstanceOf(IllegalStateException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "status", "scope", "idle-expiry" })
	void queryableFamilyChangesCannotReplaceItsEncryptedNativeBounds(String changed) {
		String code = code(Set.of("openid", "profile", "offline_access")); exchange(request(code, authenticatedClient(code)));
		var authorization = stored(code).authorization();
		this.jdbc.sql("ALTER TABLE iam_refresh_family DISABLE TRIGGER iam_refresh_family_protection").update();
		try {
			switch (changed) {
				case "status" -> this.jdbc.sql("UPDATE iam_refresh_family SET version=version+1,status='quarantined'").update();
				case "scope" -> this.jdbc.sql("UPDATE iam_refresh_family SET version=version+1,scopes='offline_access,openid'").update();
				default -> this.jdbc.sql("UPDATE iam_refresh_family SET version=version+1,idle_expires_at=idle_expires_at-INTERVAL '1 second'").update();
			}
			assertThatIllegalStateException().isThrownBy(() -> this.refresh.findByAuthorization(authorization)).withMessage("Refresh family does not match protected state");
		}
		finally { this.jdbc.sql("ALTER TABLE iam_refresh_family ENABLE TRIGGER iam_refresh_family_protection").update(); }
	}

	@Test
	void aSpentHistoryTimestampWithoutAValidSealCannotChangeTheMeaningOfATokenLookup() {
		String code = code(Set.of("openid", "offline_access")); var result = exchange(request(code, authenticatedClient(code)));
		this.jdbc.sql("UPDATE iam_refresh_history SET consumed_at=clock_timestamp(),seal=:seal").param("seal", "0".repeat(64)).update();
		assertThatIllegalStateException().isThrownBy(() -> this.refresh.findByToken(result.getRefreshToken().getTokenValue()))
				.withMessage("Refresh history does not match protected state");
		assertThatIllegalStateException().isThrownBy(() -> this.refresh.findByAuthorization(stored(code).authorization()))
				.withMessage("Refresh history does not match protected state");
	}

	@Test
	void anEncryptedNativeRecordCannotOmitItsExistingFamilyMetadata() {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code)); exchange(request);
		var current = stored(code);
		var altered = this.authorizations.save(OAuth2Authorization.from(current.authorization()).attributes(attributes -> attributes.remove("iam.refreshFamily")).build(), current.version());
		assertThatIllegalStateException().isThrownBy(() -> this.refresh.findByAuthorization(altered.authorization())).withMessage("Refresh family does not match protected state");
		rejection(request, "server_error"); assertThat(stored(code).version()).isEqualTo(altered.version());
	}

	@ParameterizedTest
	@ValueSource(strings = { "family", "history" })
	void refreshReplayEvidenceCannotBeDeletedBeforeItsAbsoluteDetectionWindow(String table) {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code)));
		assertThatThrownBy(() -> this.jdbc.sql("DELETE FROM iam_refresh_" + table).update()).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).isPresent();
	}

	@Test
	void databaseConstraintsRejectSkippedGenerationsUnspentParentsAndMultipleSuccessors() {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code)));
		var family = this.refresh.findByAuthorization(stored(code).authorization()).orElseThrow();
		assertThatThrownBy(() -> insertUntrustedChild(family, "1".repeat(64), 1)).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
		this.jdbc.sql("UPDATE iam_refresh_history SET consumed_at=clock_timestamp(),seal=:seal").param("seal", "0".repeat(64)).update();
		assertThatThrownBy(() -> insertUntrustedChild(family, "2".repeat(64), 2)).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
		assertThat(insertUntrustedChild(family, "1".repeat(64), 1)).isEqualTo(1);
		assertThatThrownBy(() -> insertUntrustedChild(family, "3".repeat(64), 1)).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "suppressed", "altered", "deferred" })
	void aFamilyQuarantineWriteFailureCannotCommitPartialNativeRevocation(String failure) {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code)); exchange(request);
		switch (failure) {
			case "suppressed" -> fault("iam_refresh_family", "BEFORE UPDATE", "RETURN NULL;", false);
			case "altered" -> fault("iam_refresh_family", "BEFORE UPDATE", "NEW.updated_at=NEW.updated_at+INTERVAL '1 millisecond'; RETURN NEW;", false);
			default -> fault("iam_refresh_family", "AFTER UPDATE", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
		}
		rejection(request, "server_error");
		assertThat(stored(code).version()).isEqualTo(2); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().satisfies(family -> {
			assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.ACTIVE); assertThat(family.version()).isEqualTo(1);
		});
	}

	@Test
	void codeReplayWithoutAnOfflineGrantStillRevokesAccessAndIdTokens() {
		String code = code(Set.of("openid")); var request = request(code, authenticatedClient(code)); exchange(request);
		rejection(request, "invalid_grant");
		assertThat(stored(code).authorization().getAccessToken().isInvalidated()).isTrue(); assertThat(stored(code).authorization().getToken(OidcIdToken.class).isInvalidated()).isTrue();
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).isEmpty();
	}

	private String concurrentExchange(OAuth2AuthorizationCodeAuthenticationToken request, CountDownLatch start) {
		awaitLatch(start); serverContext("https://iam.example");
		try { exchange(request); return "success"; }
		catch (OAuth2AuthenticationException ex) { return ex.getError().getErrorCode(); }
		finally { AuthorizationServerContextHolder.resetContext(); }
	}
	private void mutate(String mutation) {
		switch (mutation) {
			case "user-disabled" -> this.jdbc.sql("UPDATE iam_user SET status='disabled' WHERE id=:id").param("id", this.userId).update();
			case "credential" -> this.jdbc.sql("UPDATE iam_password SET credential_version=credential_version+1 WHERE user_id=:id").param("id", this.userId).update();
			case "client-secret" -> this.clients.rotateSecret(this.clientId, 1, AUDIT);
			case "client-disabled" -> this.clients.setEnabled(this.clientId, 1, false, AUDIT);
			case "client-transferred" -> this.clients.updateConfiguration(this.clientId, 1, configuration(this.resources.create("urn:example:billing", "Billing", AUDIT).id(), Set.of()), AUDIT);
			case "resource" -> this.resources.updateDisplayName(this.resourceId, 1, "New orders", AUDIT);
			case "resource-disabled" -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
			case "role" -> this.roles.updateDisplayName(this.roleId, 1, "New reader", AUDIT);
			case "role-disabled" -> this.roles.setEnabled(this.roleId, 1, false, AUDIT);
			default -> this.assignments.change(this.userId, this.roleId, 1, false, AUDIT);
		}
	}
	private String code(Set<String> scopes) {
		var browser = UsernamePasswordAuthenticationToken.authenticated(this.userId, "browser-credential", List.of(new SimpleGrantedAuthority("ROLE_IAM_ADMIN")));
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", this.clientId.toString(), browser,
				REDIRECT, "opaque-client-state", scopes, Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE));
		request.setDetails(new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()));
		return ((OAuth2AuthorizationCodeRequestAuthenticationToken) this.requests.authenticate(request)).getAuthorizationCode().getTokenValue();
	}
	private OAuth2AuthorizationCodeAuthenticationToken request(String code, Authentication client) {
		var request = new OAuth2AuthorizationCodeAuthenticationToken(code, client, REDIRECT, Map.of("code_verifier", VERIFIER));
		request.setDetails(new IdentityAuthorizationCodeProvider.RequestEvidence(UUID.randomUUID())); return request;
	}
	private OAuth2ClientAuthenticationToken authenticatedClient(String code) { return authenticatedClient(this.clientId, this.secret, code); }
	private OAuth2ClientAuthenticationToken authenticatedClient(UUID id, String secret, String code) {
		var readOnly = new OAuth2AuthorizationService() {
			@Override public void save(OAuth2Authorization authorization) { throw new AssertionError("Client proof cannot save grants"); }
			@Override public void remove(OAuth2Authorization authorization) { throw new AssertionError("Client proof cannot remove grants"); }
			@Override public OAuth2Authorization findById(String value) { throw new AssertionError("Client proof cannot enumerate grants"); }
			@Override public OAuth2Authorization findByToken(String value, OAuth2TokenType type) { return IdentityAuthorizationCodeProviderIntegrationTests.this.authorizations.findByToken(value, type.getValue()).map(IdentityAuthorizations.Snapshot::authorization).orElse(null); }
		};
		return (OAuth2ClientAuthenticationToken) new IdentityClientAuthenticationProvider(this.protocol, readOnly).authenticate(new OAuth2ClientAuthenticationToken(id.toString(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret,
				Map.of("grant_type", "authorization_code", "code", code, "code_verifier", VERIFIER)));
	}
	private OAuth2AccessTokenAuthenticationToken exchange(OAuth2AuthorizationCodeAuthenticationToken request) { return (OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(request); }
	private OAuth2AuthenticationException rejection(OAuth2AuthorizationCodeAuthenticationToken request, String code) {
		var exception = catchThrowableOfType(OAuth2AuthenticationException.class, () -> this.provider.authenticate(request));
		assertThat(exception).isNotNull(); assertThat(exception.getError().getErrorCode()).isEqualTo(code); assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).doesNotContain(VERIFIER, this.secret, this.sessionId, "isolated exchange", "ignored-extension"); return exception;
	}
	private IdentityAuthorizations.Snapshot stored(String code) { return this.authorizations.findByToken(code, "code").orElseThrow(); }
	private void assertUnconsumed(String code) {
		var stored = stored(code); assertThat(stored.version()).isEqualTo(1);
		assertThat(stored.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isFalse();
		assertThat(stored.authorization().getAccessToken()).isNull(); assertThat(stored.authorization().getRefreshToken()).isNull(); assertThat(stored.authorization().getToken(OidcIdToken.class)).isNull();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_family").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isZero();
	}
	private void assertRevoked(String code) {
		var stored = stored(code).authorization(); assertThat(stored.getAccessToken().isInvalidated()).isTrue();
		assertThat(stored.getRefreshToken().isInvalidated()).isTrue(); assertThat(stored.getToken(OidcIdToken.class).isInvalidated()).isTrue();
	}
	private JWTClaimsSet verified(String value, String type) throws Exception {
		var jwt = SignedJWT.parse(value); assertThat(jwt.verify(new RSASSAVerifier(this.signing.publicKey()))).isTrue();
		assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256"); assertThat(jwt.getHeader().getType().toString()).isEqualTo(type);
		assertThat(jwt.getHeader().getKeyID()).isEqualTo(this.signing.id().toString()); return jwt.getJWTClaimsSet();
	}
	private UUID activeUser(String name) {
		var user = this.users.create(name, name, AUDIT); var setup = this.setups.issue(user.id(), AUDIT);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:exchange", UUID.randomUUID()); return user.id();
	}
	private String browserSession(UUID userId, long authenticatedAt) {
		var session = this.store.createSession(); session.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT,
				new SecurityContextImpl(UsernamePasswordAuthenticationToken.authenticated(userId, null, List.of())));
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, authenticatedAt); session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1L);
		this.store.save(session); return session.getId();
	}
	private void sessionAttribute(String name, long value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes=:value WHERE attribute_name=:name AND session_primary_id=(SELECT primary_id FROM iam_browser_session WHERE session_id=:id)")
				.param("value", SerializationUtils.serialize(value)).param("name", name).param("id", this.sessionId).update();
	}
	private int insertUntrustedChild(IdentityRefreshFamily family, String digest, long generation) {
		return this.jdbc.sql("""
				INSERT INTO iam_refresh_history(digest,authorization_id,generation,parent_digest,issued_at,expires_at,seal)
				SELECT :digest,authorization_id,:generation,current_digest,clock_timestamp(),idle_expires_at,:seal FROM iam_refresh_family WHERE authorization_id=:id
				""").param("digest", digest).param("generation", generation).param("seal", "f".repeat(64)).param("id", family.authorizationId().toString()).update();
	}
	private List<Map<String, Object>> tokenAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('tokens_issued','authorization_code_replayed','token_request_rejected') ORDER BY recorded_at,id").query().listOfRows(); }
	private void fault(String table, String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION exchange_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").update();
		this.jdbc.sql("CREATE " + (deferred ? "CONSTRAINT " : "") + "TRIGGER exchange_test_fault " + timing + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION exchange_test_fault()").update();
	}
	private static IdentityClientConfiguration configuration(UUID resource, Set<UUID> roles) {
		return new IdentityClientConfiguration("Orders", resource, List.of(REDIRECT), Set.of("openid", "profile", "offline_access"), roles);
	}
	private static void serverContext(String issuer) {
		var settings = AuthorizationServerSettings.builder().issuer(issuer).build();
		AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
			@Override public String getIssuer() { return settings.getIssuer(); }
			@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return settings; }
		});
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent exchange did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static Path keyFile(int length) {
		try {
			Path path = Files.createTempFile("iam-code-exchange-", ".key"); byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
