package com.ixayda.iam.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
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
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
abstract class IdentityProtocolTestSupport {

	static final Path SIGNING_KEY = keyFile(32);
	static final Path AUTHORIZATION_KEY = keyFile(64);
	static final String PASSWORD = "saffron village ripple lantern 936";
	static final String REDIRECT = "https://orders.example/callback";
	static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	static final String NONCE = "oidc-code-exchange-nonce";
	static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:protocol-test", "internal:protocol", UUID.randomUUID());
	@Autowired IdentityApplicationRoles applications;
	@Autowired IdentityAuthorizationSessions sessions;
	@Autowired IdentityAuthorizations authorizations;
	@Autowired IdentityAuthorizationBindings bindings;
	@Autowired IdentityProtocolClients protocol;
	@Autowired IdentityRefreshTokens refresh;
	@Autowired IdentityClients clients;
	@Autowired IdentityUsers users;
	@Autowired IdentityUserSetups setups;
	@Autowired IdentityResources resources;
	@Autowired IdentityResourceRoles roles;
	@Autowired IdentityUserRoles assignments;
	@Autowired IdentitySigningKeys keys;
	@Autowired SecurityAudits audits;
	@Autowired JdbcClient jdbc;
	@Autowired JdbcTemplate template;
	@Autowired PlatformTransactionManager transactions;
	@Autowired ApplicationContext context;
	IdentityAuthorizationCodeProvider provider;
	IdentityAuthorizationRequestProvider requests;
	SessionRepository<Session> store;
	IdentitySigningKey signing;
	UUID userId;
	UUID resourceId;
	UUID roleId;
	UUID clientId;
	String secret;
	String sessionId;
	long authenticatedAt;

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
	void mutate(String mutation) {
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
	String code(Set<String> scopes) {
		var browser = UsernamePasswordAuthenticationToken.authenticated(this.userId, "browser-credential", List.of(new SimpleGrantedAuthority("ROLE_IAM_ADMIN")));
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", this.clientId.toString(), browser,
				REDIRECT, "opaque-client-state", scopes, Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE));
		request.setDetails(new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()));
		return ((OAuth2AuthorizationCodeRequestAuthenticationToken) this.requests.authenticate(request)).getAuthorizationCode().getTokenValue();
	}
	OAuth2AuthorizationCodeAuthenticationToken request(String code, Authentication client) {
		var request = new OAuth2AuthorizationCodeAuthenticationToken(code, client, REDIRECT, Map.of("code_verifier", VERIFIER));
		request.setDetails(new IdentityAuthorizationCodeProvider.RequestEvidence(UUID.randomUUID())); return request;
	}
	OAuth2ClientAuthenticationToken authenticatedClient(String code) { return authenticatedClient(this.clientId, this.secret, code); }
	OAuth2ClientAuthenticationToken authenticatedClient(UUID id, String secret, String code) {
		var readOnly = new OAuth2AuthorizationService() {
			@Override public void save(OAuth2Authorization authorization) { throw new AssertionError("Client proof cannot save grants"); }
			@Override public void remove(OAuth2Authorization authorization) { throw new AssertionError("Client proof cannot remove grants"); }
			@Override public OAuth2Authorization findById(String value) { throw new AssertionError("Client proof cannot enumerate grants"); }
			@Override public OAuth2Authorization findByToken(String value, OAuth2TokenType type) { return IdentityProtocolTestSupport.this.authorizations.findByToken(value, type.getValue()).map(IdentityAuthorizations.Snapshot::authorization).orElse(null); }
		};
		return (OAuth2ClientAuthenticationToken) new IdentityClientAuthenticationProvider(this.protocol, readOnly).authenticate(new OAuth2ClientAuthenticationToken(id.toString(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, secret,
				Map.of("grant_type", "authorization_code", "code", code, "code_verifier", VERIFIER)));
	}
	OAuth2AccessTokenAuthenticationToken exchange(OAuth2AuthorizationCodeAuthenticationToken request) { return (OAuth2AccessTokenAuthenticationToken) this.provider.authenticate(request); }
	OAuth2AuthenticationException rejection(OAuth2AuthorizationCodeAuthenticationToken request, String code) {
		var exception = catchThrowableOfType(OAuth2AuthenticationException.class, () -> this.provider.authenticate(request));
		assertThat(exception).isNotNull(); assertThat(exception.getError().getErrorCode()).isEqualTo(code); assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).doesNotContain(VERIFIER, this.secret, this.sessionId, "isolated exchange", "ignored-extension"); return exception;
	}
	IdentityAuthorizations.Snapshot stored(String code) { return this.authorizations.findByToken(code, "code").orElseThrow(); }
	void assertUnconsumed(String code) {
		var stored = stored(code); assertThat(stored.version()).isEqualTo(1);
		assertThat(stored.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isFalse();
		assertThat(stored.authorization().getAccessToken()).isNull(); assertThat(stored.authorization().getRefreshToken()).isNull(); assertThat(stored.authorization().getToken(OidcIdToken.class)).isNull();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_family").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isZero();
	}
	void assertRevoked(String code) {
		var stored = stored(code).authorization(); assertThat(stored.getAccessToken().isInvalidated()).isTrue();
		assertThat(stored.getRefreshToken().isInvalidated()).isTrue(); assertThat(stored.getToken(OidcIdToken.class).isInvalidated()).isTrue();
	}
	JWTClaimsSet verified(String value, String type) throws Exception {
		var jwt = SignedJWT.parse(value); assertThat(jwt.verify(new RSASSAVerifier(this.signing.publicKey()))).isTrue();
		assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256"); assertThat(jwt.getHeader().getType().toString()).isEqualTo(type);
		assertThat(jwt.getHeader().getKeyID()).isEqualTo(this.signing.id().toString()); return jwt.getJWTClaimsSet();
	}
	UUID activeUser(String name) {
		var user = this.users.create(name, name, AUDIT); var setup = this.setups.issue(user.id(), AUDIT);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:exchange", UUID.randomUUID()); return user.id();
	}
	String browserSession(UUID userId, long authenticatedAt) {
		var session = this.store.createSession(); session.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT,
				new SecurityContextImpl(UsernamePasswordAuthenticationToken.authenticated(userId, null, List.of())));
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, authenticatedAt); session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1L);
		this.store.save(session); return session.getId();
	}
	void sessionAttribute(String name, long value) {
		this.jdbc.sql("UPDATE iam_browser_session_attributes SET attribute_bytes=:value WHERE attribute_name=:name AND session_primary_id=(SELECT primary_id FROM iam_browser_session WHERE session_id=:id)")
				.param("value", SerializationUtils.serialize(value)).param("name", name).param("id", this.sessionId).update();
	}
	int insertUntrustedChild(IdentityRefreshFamily family, String digest, long generation) {
		return this.jdbc.sql("""
				INSERT INTO iam_refresh_history(digest,authorization_id,generation,parent_digest,issued_at,expires_at,seal)
				SELECT :digest,authorization_id,:generation,current_digest,clock_timestamp(),idle_expires_at,:seal FROM iam_refresh_family WHERE authorization_id=:id
				""").param("digest", digest).param("generation", generation).param("seal", "f".repeat(64)).param("id", family.authorizationId().toString()).update();
	}
	List<Map<String, Object>> tokenAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('tokens_issued','authorization_code_replayed','token_request_rejected') ORDER BY recorded_at,id").query().listOfRows(); }
	void fault(String table, String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION exchange_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").update();
		this.jdbc.sql("CREATE " + (deferred ? "CONSTRAINT " : "") + "TRIGGER exchange_test_fault " + timing + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION exchange_test_fault()").update();
	}
	static IdentityClientConfiguration configuration(UUID resource, Set<UUID> roles) {
		return new IdentityClientConfiguration("Orders", resource, List.of(REDIRECT), Set.of("openid", "profile", "offline_access"), roles);
	}
	static void serverContext(String issuer) {
		var settings = AuthorizationServerSettings.builder().issuer(issuer).build();
		AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
			@Override public String getIssuer() { return settings.getIssuer(); }
			@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return settings; }
		});
	}
	static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent exchange did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	static Path keyFile(int length) {
		try {
			Path path = Files.createTempFile("iam-code-exchange-", ".key"); byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
