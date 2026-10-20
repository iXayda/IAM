package com.ixayda.iam.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
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
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAuthorizationBindings;
import com.ixayda.iam.service.IdentityAuthorizations;
import com.ixayda.iam.service.IdentityAuthorizationSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityProtocolClients;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.IdentityUserRoles;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.SecurityAudits;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
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
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthorizationRequestProviderIntegrationTests {

	private static final Path SIGNING_KEY = keyFile(32);
	private static final Path AUTHORIZATION_KEY = keyFile(64);
	private static final String PASSWORD = "Ceramic orchard quartz river 87";
	private static final String AUTHORIZE = "https://iam.example/oauth2/authorize";
	private static final String REDIRECT = "https://orders.example/callback";
	private static final String STATE = "isolated-client-state-87576";
	private static final String NONCE = "isolated-client-nonce-98674";
	private static final String CHALLENGE = "f".repeat(42) + "c";
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:authorization-request-test", "internal:authorization-request", UUID.randomUUID());
	@Autowired private IdentityProtocolClients protocol;
	@Autowired private IdentityAuthorizationSessions sessions;
	@Autowired private IdentityAuthorizationBindings bindings;
	@Autowired private IdentityAuthorizations authorizations;
	@Autowired private SecurityAudits audits;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUserRoles assignments;
	@Autowired private IdentitySigningKeys keys;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private ApplicationContext context;
	private IdentityAuthorizationRequestProvider provider;
	private SessionRepository<Session> store;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;
	private UUID clientId;
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
		this.keys.initialize(); this.userId = activeUser("alice");
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
		this.assignments.change(this.userId, this.roleId, 0, true, AUDIT);
		this.clientId = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT).client().id();
		var official = new JdbcIndexedSessionRepository(this.template, new TransactionTemplate(this.transactions));
		official.setTableName("iam_browser_session"); official.setDefaultMaxInactiveInterval(Duration.ofMinutes(30));
		this.store = (SessionRepository<Session>) (SessionRepository<?>) official;
		this.authenticatedAt = System.currentTimeMillis() - 1000;
		var session = this.store.createSession();
		session.setAttribute(IdentityBrowserSessions.SECURITY_CONTEXT, new SecurityContextImpl(browser()));
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt);
		session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1L);
		this.store.save(session); this.sessionId = session.getId();
		this.provider = new IdentityAuthorizationRequestProvider(this.protocol, this.sessions, this.bindings, this.audits, this.transactions);
		serverContext();
	}

	@AfterEach
	void cleanFaultsAndReferences() {
		AuthorizationServerContextHolder.resetContext();
		for (String table : List.of("iam_authorization_binding", "iam_authorization_binding_role", "iam_security_audit")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS code_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS code_test_fault()").update();
		this.jdbc.sql("DROP SEQUENCE IF EXISTS code_test_audit_probe").update();
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user_role,iam_user_resource_role_revision,iam_browser_session CASCADE").update();
	}

	@Test
	void nativeCodeGenerationPersistsOriginalBoundsAndMinimalStringAuthenticationBeforeReturning() {
		var request = request();
		var result = authenticate(request);
		assertThat(result.getRedirectUri()).isEqualTo(REDIRECT); assertThat(result.getState()).isEqualTo(STATE);
		assertThat(result.getScopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
		assertThat(Base64.getUrlDecoder().decode(result.getAuthorizationCode().getTokenValue())).hasSize(96);
		var stored = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow();
		assertThat(stored.authorization().getToken(OAuth2AuthorizationCode.class).getToken()).isEqualTo(result.getAuthorizationCode());
		var binding = this.bindings.findByAuthorization(stored.authorization()).orElseThrow();
		assertThat(binding.session().access().userId()).isEqualTo(this.userId);
		assertThat(binding.session().access().clientId()).isEqualTo(this.clientId);
		assertThat(binding.session().access().resourceId()).isEqualTo(this.resourceId);
		assertThat(binding.session().access().audience()).isEqualTo("urn:example:orders");
		assertThat(binding.session().access().roles()).extracting(role -> role.code()).containsExactly("reader");
		assertThat(binding.session().access().assignmentVersion()).isEqualTo(1);
		assertThat(binding.session().authenticatedAt()).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt));
		assertThat(binding.scopes()).containsExactlyInAnyOrderElementsOf(request.getScopes());
		assertThat(binding.codeExpiresAt()).isEqualTo(binding.issuedAt().plusSeconds(60));
		assertThat(binding.session().browserSessionId().toString()).isNotEqualTo(this.sessionId);
		Authentication principal = stored.authorization().getAttribute(Principal.class.getName());
		assertThat(principal.getPrincipal()).isEqualTo(this.userId.toString()); assertThat(principal.getCredentials()).isNull(); assertThat(principal.getDetails()).isNull();
		assertThat(principal.getAuthorities()).singleElement().isInstanceOfSatisfying(FactorGrantedAuthority.class, factor -> {
			assertThat(factor.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY); assertThat(factor.getIssuedAt()).isEqualTo(binding.session().authenticatedAt());
		});
		assertThat(result.getPrincipal()).isEqualTo(principal); assertThat(result.getDetails()).isNull();
		assertThat(stored.authorization().getAttributes().toString()).doesNotContain(this.sessionId, "browser-credential", "transport-secret", "ROLE_IAM_ADMIN");
		OAuth2AuthorizationRequest authorizationRequest = stored.authorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(authorizationRequest.getAdditionalParameters()).containsEntry("nonce", NONCE).containsEntry("code_challenge", CHALLENGE).containsEntry("code_challenge_method", "S256");
		assertThat(protocolAudits()).singleElement().satisfies(event -> {
			assertThat(event.get("action")).isEqualTo("authorization_code_issued"); assertThat(event.get("outcome")).isEqualTo("success");
			assertThat(event.get("target_user_id")).isEqualTo(this.userId); assertThat(event.get("correlation_id")).isEqualTo(((IdentityAuthorizationRequestProvider.BrowserEvidence) request.getDetails()).correlationId());
		});
		assertThat(this.context.getBeansOfType(RegisteredClientRepository.class)).isEmpty();
		assertThat(this.context.getBeansOfType(OAuth2AuthorizationService.class)).isEmpty();
		assertThat(this.context.getBeansOfType(IdentityAuthorizationRequestProvider.class)).isEmpty();
	}

	@Test
	void exactOriginalResourceAndRoleBoundsRemainAvailableAfterAClientTransferOrAssignmentChange() {
		var result = authenticate(request());
		var nativeRecord = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization();
		var original = this.bindings.findByAuthorization(nativeRecord).orElseThrow();
		var billing = this.resources.create("urn:example:billing", "Billing", AUDIT);
		this.clients.updateConfiguration(this.clientId, 1, configuration(billing.id(), Set.of()), AUDIT);
		this.assignments.change(this.userId, this.roleId, 1, false, AUDIT);
		var reloaded = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization();
		assertThat(this.bindings.findByAuthorization(reloaded)).contains(original);
		assertThat(original.session().access().resourceId()).isEqualTo(this.resourceId);
		assertThat(original.session().access().roles()).hasSize(1);
		this.store.deleteById(this.sessionId);
		assertThat(this.bindings.findByAuthorization(reloaded)).contains(original);
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 100 })
	void originalRoleBoundsRetainTheCompleteAllowedSetIncludingAnEmptyIdentityOnlyProjection(int count) {
		var allowed = new java.util.HashSet<UUID>();
		for (int index = 0; index < count; index++) {
			var role = this.roles.create(this.resourceId, "role_" + String.format(java.util.Locale.ROOT, "%03d", index), "Role " + index, AUDIT);
			allowed.add(role.id()); this.assignments.change(this.userId, role.id(), index + 1, true, AUDIT);
		}
		this.clients.updateConfiguration(this.clientId, 1, configuration(this.resourceId, allowed), AUDIT);
		var result = authenticate(request());
		var original = this.bindings.findByAuthorization(this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization()).orElseThrow();
		assertThat(original.session().access().roles()).hasSize(count);
		assertThat(original.session().access().roles()).extracting(role -> role.id()).containsExactlyInAnyOrderElementsOf(allowed);
		assertThat(original.session().access().assignmentVersion()).isEqualTo(count + 1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "state-missing", "state-empty", "state-control", "state-large", "nonce-large", "scope-missing", "scope-extra", "plain", "challenge-missing", "challenge-empty", "challenge-short", "challenge-noncanonical", "method-missing", "method-empty", "parameter-array", "unknown-array", "unknown-empty-array", "request", "request_uri", "resource", "audience", "response-mode", "prompt-unknown", "prompt-combined-none", "prompt-duplicate", "prompt-spaces", "max-age-negative", "max-age-decimal", "max-age-overflow" })
	void invalidScopesAndMalformedOrUnsupportedParametersProduceNoGrantAndCommitAFixedFailureAudit(String invalid) {
		var parameters = new HashMap<>(parameters()); String state = STATE; Set<String> scopes = Set.of("openid", "profile");
		switch (invalid) {
			case "state-missing" -> state = null;
			case "state-empty" -> state = "";
			case "state-control" -> state = "bad\nstate";
			case "state-large" -> state = "s".repeat(513);
			case "nonce-large" -> parameters.put("nonce", "n".repeat(257));
			case "scope-missing" -> scopes = Set.of("profile");
			case "scope-extra" -> scopes = Set.of("openid", "email");
			case "plain" -> parameters.put("code_challenge_method", "plain");
			case "challenge-missing" -> parameters.remove("code_challenge");
			case "challenge-empty" -> parameters.put("code_challenge", "");
			case "challenge-short" -> parameters.put("code_challenge", "f".repeat(42));
			case "challenge-noncanonical" -> parameters.put("code_challenge", "f".repeat(43));
			case "method-missing" -> parameters.remove("code_challenge_method");
			case "method-empty" -> parameters.put("code_challenge_method", "");
			case "parameter-array" -> parameters.put("nonce", new String[] { "one", "two" });
			case "unknown-array" -> parameters.put("unknown", new String[] { "one", "two" });
			case "unknown-empty-array" -> parameters.put("unknown", new String[] { "", "" });
			case "response-mode" -> parameters.put("response_mode", "form_post");
			case "prompt-unknown" -> parameters.put("prompt", "authorize");
			case "prompt-combined-none" -> parameters.put("prompt", "none login");
			case "prompt-duplicate" -> parameters.put("prompt", "login login");
			case "prompt-spaces" -> parameters.put("prompt", " login");
			case "max-age-negative" -> parameters.put("max_age", "-1");
			case "max-age-decimal" -> parameters.put("max_age", "1.2");
			case "max-age-overflow" -> parameters.put("max_age", "9223372036854775808");
			default -> parameters.put(invalid, "untrusted-extension");
		}
		var request = request(this.clientId.toString(), REDIRECT, state, scopes, parameters, browser(), evidence());
		var exception = rejection(request, invalid.startsWith("scope") ? "invalid_scope" : "invalid_request");
		assertThat(exception.getAuthorizationCodeRequestAuthentication()).isNotNull();
		assertThat(exception.getAuthorizationCodeRequestAuthentication().getAdditionalParameters()).isEmpty();
		assertNoGrants(); assertThat(protocolAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("authorization_request_rejected"));
		assertThat(protocolAudits().toString()).doesNotContain("untrusted-extension", CHALLENGE, NONCE, STATE, this.sessionId, "transport-secret");
	}

	@ParameterizedTest
	@ValueSource(strings = { "nonce", "prompt", "max_age", "response_mode", "request", "request_uri", "resource", "audience" })
	void emptyOptionalParametersAreOmittedFromThePersistedOriginalRequest(String name) {
		var parameters = new HashMap<>(parameters()); parameters.put(name, "");
		var result = authenticate(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters, browser(), evidence()));
		var stored = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization();
		OAuth2AuthorizationRequest original = stored.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(original.getAdditionalParameters()).doesNotContainKey(name).containsEntry("code_challenge", CHALLENGE);
		assertThat(this.bindings.findByAuthorization(stored)).isPresent();
		assertThat(protocolAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("authorization_code_issued"));
	}

	@Test
	void unrecognizedParametersAreIgnoredWithoutEnteringProtectedStateOrAudit() {
		var parameters = new HashMap<>(parameters());
		parameters.put("unknown", "untrusted-extension-\u2603"); parameters.put("unknown-empty", "");
		var result = authenticate(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters, browser(), evidence()));
		var stored = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization();
		OAuth2AuthorizationRequest original = stored.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(original.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(parameters());
		assertThat(original.getAuthorizationRequestUri()).doesNotContain("unknown", "untrusted-extension");
		assertThat(stored.getAttributes().toString()).doesNotContain("unknown", "untrusted-extension");
		assertThat(this.bindings.findByAuthorization(stored)).isPresent();
		assertThat(protocolAudits().toString()).doesNotContain("unknown", "untrusted-extension");
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "foreign", "suffix", "fragment", "encoding", "loopback-port", "unknown-client", "disabled-client" })
	void unregisteredCallbacksAndUnavailableClientsNeverCreateRedirectableErrors(String invalid) {
		String redirect = REDIRECT; String client = this.clientId.toString();
		switch (invalid) {
			case "missing" -> redirect = null;
			case "foreign" -> redirect = "https://attacker.example/callback";
			case "suffix" -> redirect += "/suffix";
			case "fragment" -> redirect += "#fragment";
			case "encoding" -> redirect = "https://orders.example/call%62ack";
			case "unknown-client" -> client = UUID.randomUUID().toString();
			case "disabled-client" -> this.clients.setEnabled(this.clientId, 1, false, AUDIT);
			default -> {
				var configuration = new IdentityClientConfiguration("Loopback", this.resourceId, List.of("https://127.0.0.1:8443/cb"), Set.of("openid"), Set.of());
				client = this.clients.create(configuration, AUDIT).client().id().toString(); redirect = "https://127.0.0.1:9443/cb";
			}
		}
		assertThat(rejection(request(client, redirect, STATE, Set.of("openid"), parameters(), browser(), evidence()), "invalid_request").getAuthorizationCodeRequestAuthentication()).isNull();
		assertNoGrants();
	}

	@ParameterizedTest
	@ValueSource(strings = { "anonymous", "wrong-principal", "missing-evidence", "missing-session", "foreign-session", "expired", "wrong-time", "wrong-version" })
	void callerAuthenticationAndHintsCannotReplaceACurrentOwnedPersistentBrowserSession(String invalid) {
		Authentication principal = browser(); Object evidence = evidence();
		switch (invalid) {
			case "anonymous" -> principal = UsernamePasswordAuthenticationToken.unauthenticated(this.userId, null);
			case "wrong-principal" -> principal = UsernamePasswordAuthenticationToken.authenticated(this.userId.toString(), null, List.of());
			case "missing-evidence" -> evidence = null;
			case "missing-session" -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(UUID.randomUUID().toString(), this.authenticatedAt, 1, UUID.randomUUID());
			case "foreign-session" -> this.jdbc.sql("UPDATE iam_browser_session SET principal_name=:user WHERE session_id=:id").param("user", activeUser("bobby").toString()).param("id", this.sessionId).update();
			case "expired" -> this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=0 WHERE session_id=:id").param("id", this.sessionId).update();
			case "wrong-time" -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt - 1, 1, UUID.randomUUID());
			default -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 2, UUID.randomUUID());
		}
		rejection(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters(), principal, evidence), "login_required");
		assertNoGrants(); assertThat(protocolAudits()).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "login", "consent", "select_account", "login consent", "max-age" })
	void requiredInteractionsAreNeverSilentlyTreatedAsAnAlreadySatisfiedLogin(String interaction) {
		var parameters = new HashMap<>(parameters());
		if (interaction.equals("max-age")) { parameters.put("max_age", "0"); } else { parameters.put("prompt", interaction); }
		String code = interaction.equals("consent") ? "consent_required" : interaction.equals("select_account") ? "account_selection_required" : "login_required";
		rejection(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters, browser(), evidence()), code); assertNoGrants();
	}

	@Test
	void promptNoneQueryAndALargeValidMaxAgePreserveStateAndNonceWithAnExistingSession() {
		var parameters = new HashMap<>(parameters()); parameters.put("prompt", "none"); parameters.put("response_mode", "query"); parameters.put("max_age", Long.toString(Long.MAX_VALUE));
		var first = authenticate(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters, browser(), evidence()));
		var second = authenticate(request());
		assertThat(first.getState()).isEqualTo(STATE); assertThat(first.getAuthorizationCode().getTokenValue()).isNotEqualTo(second.getAuthorizationCode().getTokenValue());
		assertThat(protocolAudits()).hasSize(2);
	}

	@Test
	void remainingBrowserLifetimeCapsTheNativeAuthorizationCode() {
		long expiry = System.currentTimeMillis() + 10_000;
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", expiry).param("id", this.sessionId).update();
		var result = authenticate(request());
		assertThat(result.getAuthorizationCode().getExpiresAt()).isEqualTo(Instant.ofEpochMilli(expiry));
		assertThat(Duration.between(result.getAuthorizationCode().getIssuedAt(), result.getAuthorizationCode().getExpiresAt())).isLessThan(Duration.ofSeconds(11));
		assertThat(this.bindings.findByAuthorization(this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization())).isPresent();
	}

	@Test
	void aDeadlinePassingDuringMandatoryAuditRollsBackTheNativeRecordBindingRolesAndSuccessAudit() {
		this.jdbc.sql("CREATE SEQUENCE code_test_audit_probe").update();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN PERFORM nextval('code_test_audit_probe'); PERFORM pg_sleep(1); END IF; RETURN NEW;", false);
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=:expiry WHERE session_id=:id").param("expiry", System.currentTimeMillis() + 600).param("id", this.sessionId).update();
		rejection(request(), "login_required"); assertNoGrants();
		assertThat(this.jdbc.sql("SELECT is_called FROM code_test_audit_probe").query(Boolean.class).single()).isTrue();
		assertThat(protocolAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("authorization_request_rejected"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "none" })
	void authenticationAgeIsRecheckedAfterTheMandatorySuccessAudit(String prompt) {
		this.jdbc.sql("CREATE SEQUENCE code_test_audit_probe").update();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN PERFORM nextval('code_test_audit_probe'); PERFORM pg_sleep(2.2); END IF; RETURN NEW;", false);
		this.authenticatedAt = this.jdbc.sql("SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint").query(Long.class).single();
		var session = this.store.findById(this.sessionId);
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt); this.store.save(session);
		var parameters = new HashMap<>(parameters()); parameters.put("max_age", "2"); parameters.put("prompt", prompt);

		rejection(request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid"), parameters, browser(), evidence()), "login_required");
		assertNoGrants();
		assertThat(this.jdbc.sql("SELECT is_called FROM code_test_audit_probe").query(Boolean.class).single()).isTrue();
		assertThat(protocolAudits()).singleElement().satisfies(event -> assertThat(event.get("action")).isEqualTo("authorization_request_rejected"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "binding-suppressed", "role-suppressed", "binding-altered", "role-altered", "audit-suppressed", "commit", "audit-unavailable" })
	void suppressedAlteredDeferredAndAuditFailuresNeverExposeAPartiallyCommittedCode(String fault) {
		switch (fault) {
			case "binding-suppressed" -> fault("iam_authorization_binding", "BEFORE INSERT", "RETURN NULL;", false);
			case "role-suppressed" -> fault("iam_authorization_binding_role", "BEFORE INSERT", "RETURN NULL;", false);
			case "binding-altered" -> fault("iam_authorization_binding", "BEFORE INSERT", "NEW.assignment_version=NEW.assignment_version+1; RETURN NEW;", false);
			case "role-altered" -> fault("iam_authorization_binding_role", "BEFORE INSERT", "NEW.version=NEW.version+1; RETURN NEW;", false);
			case "audit-suppressed" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-unavailable" -> fault("iam_security_audit", "BEFORE INSERT", "RAISE EXCEPTION 'isolated audit fault';", false);
			default -> fault("iam_authorization_binding", "AFTER INSERT", "RAISE EXCEPTION 'isolated commit fault';", true);
		}
		rejection(request(), "server_error"); assertNoGrants();
		assertThat(protocolAudits()).hasSize(fault.equals("audit-unavailable") ? 0 : 1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "audience", "credential", "scopes", "role", "role-deleted" })
	void mutableDatabaseCopiesCannotReplaceTheBoundsInsideEncryptedNativeState(String corruption) {
		var result = authenticate(request());
		var nativeRecord = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization();
		String table = corruption.startsWith("role") ? "iam_authorization_binding_role" : "iam_authorization_binding";
		String trigger = corruption.startsWith("role") ? "iam_authorization_binding_role_protection" : "iam_authorization_binding_protection";
		this.jdbc.sql("ALTER TABLE " + table + " DISABLE TRIGGER " + trigger).update();
		try {
			switch (corruption) {
				case "audience" -> this.jdbc.sql("UPDATE iam_authorization_binding SET audience='urn:example:injected'").update();
				case "credential" -> this.jdbc.sql("UPDATE iam_authorization_binding SET credential_version=credential_version+1").update();
				case "scopes" -> this.jdbc.sql("UPDATE iam_authorization_binding SET scopes='openid'").update();
				case "role" -> this.jdbc.sql("UPDATE iam_authorization_binding_role SET version=version+1").update();
				default -> this.jdbc.sql("DELETE FROM iam_authorization_binding_role").update();
			}
			assertThatIllegalStateException().isThrownBy(() -> this.bindings.findByAuthorization(nativeRecord)).withMessage("Authorization binding does not match protected state");
		}
		finally { this.jdbc.sql("ALTER TABLE " + table + " ENABLE TRIGGER " + trigger).update(); }
	}

	@Test
	void databaseTriggersAndForeignKeysPreserveOriginalBoundsAndPreventPrematureNativeDeletion() {
		var result = authenticate(request());
		var saved = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_authorization_binding SET credential_version=credential_version+1").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE iam_authorization_binding_role SET version=version+1").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.authorizations.remove(UUID.fromString(saved.authorization().getId()), saved.version())).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(this.bindings.findByAuthorization(this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow().authorization())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "redirect", "state", "nonce", "challenge", "scope", "client", "uri", "request-uri" })
	void subsequentNativeStorageUpdatesCannotSilentlyReplaceTheOriginalAuthorizationRequest(String changed) {
		var result = authenticate(request());
		var snapshot = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow();
		OAuth2AuthorizationRequest original = snapshot.authorization().getAttribute(OAuth2AuthorizationRequest.class.getName());
		var builder = OAuth2AuthorizationRequest.from(original);
		switch (changed) {
			case "redirect" -> builder.redirectUri("https://orders.example/different");
			case "state" -> builder.state("different-client-state");
			case "nonce" -> builder.additionalParameters(parameters -> parameters.put("nonce", "different-nonce"));
			case "challenge" -> builder.additionalParameters(parameters -> parameters.put("code_challenge", "A".repeat(43)));
			case "scope" -> builder.scopes(Set.of("openid"));
			case "client" -> builder.clientId(UUID.randomUUID().toString());
			case "request-uri" -> builder.authorizationRequestUri("https://attacker.example/oauth2/authorize?injected=true");
			default -> builder.authorizationUri("https://attacker.example/oauth2/authorize");
		}
		var altered = org.springframework.security.oauth2.server.authorization.OAuth2Authorization.from(snapshot.authorization())
				.attribute(OAuth2AuthorizationRequest.class.getName(), builder.build()).build();
		var stored = this.authorizations.save(altered, snapshot.version()).authorization();
		assertThatIllegalStateException().isThrownBy(() -> this.bindings.findByAuthorization(stored)).withMessage("Authorization binding does not match protected state");
	}

	@Test
	void invalidatingACodePreservesOriginalBoundsButReplacingItsValueCannotCreateAnotherUsableCode() {
		var result = authenticate(request());
		var snapshot = this.authorizations.findByToken(result.getAuthorizationCode().getTokenValue(), "code").orElseThrow();
		var original = this.bindings.findByAuthorization(snapshot.authorization()).orElseThrow();
		var invalidated = this.authorizations.save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.from(snapshot.authorization())
				.invalidate(result.getAuthorizationCode()).build(), snapshot.version());
		assertThat(this.bindings.findByAuthorization(invalidated.authorization())).contains(original);
		var code = result.getAuthorizationCode();
		var replaced = this.authorizations.save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization.from(invalidated.authorization())
				.token(new OAuth2AuthorizationCode("different-authorization-code", code.getIssuedAt(), code.getExpiresAt())).build(), invalidated.version());
		assertThatIllegalStateException().isThrownBy(() -> this.bindings.findByAuthorization(replaced.authorization())).withMessage("Authorization binding does not match protected state");
	}

	@Test
	void configurationChangesCommittedWhileWaitingForTheSubjectCannotAuthenticateAnotherSnapshot() throws Exception {
		var locked = new CountDownLatch(1); var change = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
					locked.countDown(); awaitLatch(change); this.clients.rotateSecret(this.clientId, 1, AUDIT);
				}));
				awaitLatch(locked);
				var issuer = executor.submit(() -> { serverContext(); try { return rejection(request(), "login_required"); } finally { AuthorizationServerContextHolder.resetContext(); } });
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR UPDATE%')").query(Boolean.class).single());
				change.countDown(); writer.get(10, TimeUnit.SECONDS); assertThat(issuer.get(10, TimeUnit.SECONDS)).isNotNull(); assertNoGrants();
			}
			finally { change.countDown(); }
		}
	}

	@Test
	void noAmbientTransactionCanPublishAnAuthorizationBeforeItsOwnWorkflowCommits() {
		assertThat(this.provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ignored", null))).isNull();
		assertThat(this.provider.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class)).isTrue();
		assertThat(this.provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> rejection(request(), "server_error")); assertNoGrants();
	}

	@ParameterizedTest
	@ValueSource(strings = { "host", "missing-context", "inferred-issuer" })
	void authorizationRequestsRequireTheExplicitHttpsIssuerInsteadOfTrustingTransportHostInformation(String invalid) {
		var request = request();
		if (invalid.equals("host")) {
			request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://attacker.example/oauth2/authorize", this.clientId.toString(), browser(), REDIRECT, STATE, Set.of("openid"), parameters());
			request.setDetails(evidence());
		}
		else if (invalid.equals("missing-context")) { AuthorizationServerContextHolder.resetContext(); }
		else {
			AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
				@Override public String getIssuer() { return "https://iam.example"; }
				@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return AuthorizationServerSettings.builder().build(); }
			});
		}
		rejection(request, invalid.equals("host") ? "invalid_request" : "server_error"); assertNoGrants();
	}

	private OAuth2AuthorizationCodeRequestAuthenticationToken request() {
		return request(this.clientId.toString(), REDIRECT, STATE, Set.of("openid", "profile", "offline_access"), parameters(), browser(), evidence());
	}
	private OAuth2AuthorizationCodeRequestAuthenticationToken request(String client, String redirect, String state, Set<String> scopes, Map<String, Object> parameters, Authentication browser, Object evidence) {
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken(AUTHORIZE, client, browser, redirect, state, scopes, parameters);
		request.setDetails(evidence); return request;
	}
	private Authentication browser() {
		var principal = UsernamePasswordAuthenticationToken.authenticated(this.userId, "browser-credential", List.of(new SimpleGrantedAuthority("ROLE_IAM_ADMIN")));
		principal.setDetails(Map.of("source", "transport-secret")); return principal;
	}
	private IdentityAuthorizationRequestProvider.BrowserEvidence evidence() { return new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()); }
	private static Map<String, Object> parameters() { return Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE); }
	private OAuth2AuthorizationCodeRequestAuthenticationToken authenticate(OAuth2AuthorizationCodeRequestAuthenticationToken request) { return (OAuth2AuthorizationCodeRequestAuthenticationToken) this.provider.authenticate(request); }
	private OAuth2AuthorizationCodeRequestAuthenticationException rejection(OAuth2AuthorizationCodeRequestAuthenticationToken request, String code) {
		var exception = catchThrowableOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class, () -> this.provider.authenticate(request));
		assertThat(exception).isNotNull(); assertThat(exception.getError().getErrorCode()).isEqualTo(code); assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).doesNotContain(this.sessionId, "browser-credential", "transport-secret", "isolated commit fault", "isolated audit fault"); return exception;
	}
	private UUID activeUser(String name) {
		var user = this.users.create(name, name, AUDIT); var setup = this.setups.issue(user.id(), AUDIT);
		this.setups.complete(user.id(), setup.token(), PASSWORD, "internal:authorization-request", UUID.randomUUID()); return user.id();
	}
	private static IdentityClientConfiguration configuration(UUID resource, Set<UUID> allowed) {
		return new IdentityClientConfiguration("Orders", resource, List.of(REDIRECT), Set.of("openid", "profile", "offline_access"), allowed);
	}
	private void assertNoGrants() {
		for (String table : List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index", "iam_authorization_binding", "iam_authorization_binding_role")) {
			assertThat(this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single()).as(table).isZero();
		}
	}
	private List<Map<String, Object>> protocolAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('authorization_code_issued','authorization_request_rejected') ORDER BY recorded_at,id").query().listOfRows(); }
	private void fault(String table, String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION code_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").update();
		this.jdbc.sql("CREATE " + (deferred ? "CONSTRAINT " : "") + "TRIGGER code_test_fault " + timing + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION code_test_fault()").update();
	}
	private static void serverContext() {
		var settings = AuthorizationServerSettings.builder().issuer("https://iam.example").build();
		AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
			@Override public String getIssuer() { return settings.getIssuer(); }
			@Override public AuthorizationServerSettings getAuthorizationServerSettings() { return settings; }
		});
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent workflow did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static Path keyFile(int length) {
		try {
			Path path = Files.createTempFile("iam-authorization-request-", ".key"); byte[] bytes = new byte[length];
			new SecureRandom().nextBytes(bytes); Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
