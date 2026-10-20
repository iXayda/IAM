package com.ixayda.iam.security;

import java.security.Principal;
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

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationInteraction;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository.StoredInteraction;
import com.ixayda.iam.service.IdentityAuthorizationInteractions;
import com.ixayda.iam.service.IdentityBrowserSessions;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityAuthorizationResumptionIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentityAuthorizationInteractions interactions;
	@Autowired private IdentityAuthorizationInteractionRepository interactionRepository;
	@Autowired private AuthorizationSecrets secrets;
	private IdentityAuthorizationRequestProvider interactive;
	private String owner;

	@BeforeEach
	void interactionProvider() {
		this.jdbc.sql("TRUNCATE iam_authorization_interaction").update();
		this.owner = this.interactions.newBrowserOwner();
		this.interactive = new IdentityAuthorizationRequestProvider(this.protocol, this.sessions, this.bindings, this.interactions, this.audits, this.transactions);
	}

	@AfterEach
	void removeInteractionFaults() {
		for (String table : List.of("iam_authorization_interaction", "iam_security_audit", "iam_authorization_binding", "oauth2_authorization")) {
			this.jdbc.sql("DROP TRIGGER IF EXISTS resumption_test_fault ON " + table).update();
		}
		this.jdbc.sql("DROP FUNCTION IF EXISTS resumption_test_fault()").update();
		this.jdbc.sql("DROP SEQUENCE IF EXISTS resumption_test_probe").update();
		this.jdbc.sql("TRUNCATE iam_authorization_interaction").update();
	}

	@ParameterizedTest
	@ValueSource(strings = {"consent", "select_account", "consent select_account"})
	void explicitBoundConfirmationPreservesTheOriginalRequestAndIssuesOnlyApplicationAuthority(String prompt) {
		var original = request(Map.of("prompt", prompt));
		var ticket = this.interactive.begin(original, this.owner);
		assertNoGrants();
		var result = resume(ticket);
		assertThat(this.interactions.find(this.owner, ticket.handle())).isEmpty();
		assertThat(result.getState()).isEqualTo(original.getState()); assertThat(result.getRedirectUri()).isEqualTo(REDIRECT);
		var stored = stored(result.getAuthorizationCode().getTokenValue()).authorization();
		OAuth2AuthorizationRequest persisted = stored.getAttribute(OAuth2AuthorizationRequest.class.getName());
		assertThat(persisted.getAdditionalParameters()).containsAllEntriesOf(original.getAdditionalParameters());
		assertThat(persisted.getScopes()).containsExactlyInAnyOrderElementsOf(original.getScopes());
		Authentication principal = stored.getAttribute(Principal.class.getName());
		assertThat(principal.getPrincipal()).isEqualTo(this.userId.toString()); assertThat(principal.getCredentials()).isNull(); assertThat(principal.getDetails()).isNull();
		assertThat(principal.getAuthorities()).noneSatisfy(authority -> assertThat(authority.getAuthority()).contains("ADMIN"));
		assertThat(stored.getAttributes().toString()).doesNotContain(this.owner, ticket.handle(), this.sessionId, "browser-secret", "ROLE_IAM_ADMIN");
		assertThat(protocolAudits()).singleElement().satisfies(row -> assertThat(row.get("action")).isEqualTo("authorization_code_issued"));
		var tokens = exchange(request(result.getAuthorizationCode().getTokenValue(), authenticatedClient(result.getAuthorizationCode().getTokenValue())));
		assertThat(tokens.getAccessToken()).isNotNull(); assertThat(tokens.getRefreshToken()).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = {"login", "max-age-zero", "max-age-expired", "login consent select_account"})
	void forcedOrExpiredAuthenticationRequiresALaterPersistentLoginBeforeResumption(String requirement) {
		Map<String, Object> parameters = requirement.equals("max-age-zero") ? Map.of("max_age", "0")
				: requirement.equals("max-age-expired") ? Map.of("max_age", "1") : Map.of("prompt", requirement);
		var original = request(parameters); var ticket = this.interactive.begin(original, this.owner);
		rejection(() -> resume(ticket), "login_required"); assertNoGrants(); assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
		freshLogin(ticket);
		var result = resume(ticket);
		assertThat(result.getAuthorizationCode()).isNotNull(); assertThat(this.interactions.find(this.owner, ticket.handle())).isEmpty();
		var binding = this.bindings.findByAuthorization(stored(result.getAuthorizationCode().getTokenValue()).authorization()).orElseThrow();
		assertThat(binding.session().authenticatedAt()).isAfter(ticket.interaction().createdAt()).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt));
	}

	@Test
	void anAnonymousInteractionCannotReuseAnOlderLoginEvenWithItsValidSessionFacts() {
		var original = request(Map.of());
		var anonymous = new OAuth2AuthorizationCodeRequestAuthenticationToken(original.getAuthorizationUri(), original.getClientId(),
				UsernamePasswordAuthenticationToken.unauthenticated("anonymous", null), original.getRedirectUri(), original.getState(), original.getScopes(), original.getAdditionalParameters());
		var ticket = this.interactive.begin(anonymous, this.owner);
		assertThat(ticket.interaction().originalAuthenticatedAt()).isZero();
		rejection(() -> resume(ticket), "login_required"); assertNoGrants();
		freshLogin(ticket); assertThat(resume(ticket).getAuthorizationCode()).isNotNull();
	}

	@Test
	void directAuthenticationCannotClaimAnInteractionHasBeenCompleted() {
		var ticket = this.interactive.begin(request(Map.of("prompt", "login")), this.owner); freshLogin(ticket);
		rejection(() -> this.interactive.authenticate(request(Map.of("prompt", "login"))), "login_required");
		assertNoGrants(); assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
		assertThat(resume(ticket).getAuthorizationCode()).isNotNull();
	}

	@Test
	void promptNoneNeverCreatesAnInteractionAndOriginalValidationCannotBeSkippedByBeginningOne() {
		rejection(() -> this.interactive.begin(request(Map.of("prompt", "none")), this.owner), "invalid_request");
		rejection(() -> this.interactive.begin(request(Map.of("code_challenge_method", "plain")), this.owner), "invalid_request");
		rejection(() -> this.interactive.begin(request(Map.of("max_age", "-1")), this.owner), "invalid_request");
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isZero(); assertNoGrants();
	}

	@Test
	void aLargeMaxAgeDoesNotOverflowAndSelectionMayUseTheExistingOwnedLogin() {
		var ticket = this.interactive.begin(request(Map.of("prompt", "select_account", "max_age", Long.toString(Long.MAX_VALUE))), this.owner);
		assertThat(resume(ticket).getAuthorizationCode()).isNotNull();
	}

	@ParameterizedTest
	@ValueSource(strings = {"owner", "handle", "anonymous", "missing-evidence", "wrong-time", "wrong-version", "foreign-session"})
	void interactionHandlesAndCallerHintsCannotReplaceCurrentBrowserOwnership(String invalid) {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner);
		String owner = this.owner, handle = ticket.handle(); Authentication browser = browser(); var evidence = evidence();
		switch (invalid) {
			case "owner" -> owner = this.interactions.newBrowserOwner();
			case "handle" -> handle = this.interactions.newBrowserOwner();
			case "anonymous" -> browser = null;
			case "missing-evidence" -> evidence = null;
			case "wrong-time" -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt - 1, 1, UUID.randomUUID());
			case "wrong-version" -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 2, UUID.randomUUID());
			default -> evidence = new IdentityAuthorizationRequestProvider.BrowserEvidence(browserSession(activeUser("bobby"), this.authenticatedAt), this.authenticatedAt, 1, UUID.randomUUID());
		}
		String currentOwner = owner, currentHandle = handle; Authentication currentBrowser = browser; var currentEvidence = evidence;
		rejection(() -> this.interactive.resume(currentOwner, currentHandle, currentBrowser, currentEvidence), invalid.equals("owner") || invalid.equals("handle") ? "invalid_request" : "login_required");
		assertNoGrants(); assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = {"user-disabled", "credential", "client-disabled", "resource-disabled"})
	void resumptionRechecksCurrentSecurityStateWithoutConsumingARejectedRequest(String mutation) {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner); mutate(mutation);
		rejection(() -> resume(ticket), mutation.equals("client-disabled") || mutation.equals("resource-disabled") ? "invalid_request" : "login_required");
		assertNoGrants(); assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
	}

	@Test
	void concurrentResumptionsIssueOneCodeAndDoNotQuarantineThatValidAuthorization() throws Exception {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner); var begin = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> resumeAfter(begin, ticket)); var second = executor.submit(() -> resumeAfter(begin, ticket)); begin.countDown();
			var results = java.util.stream.Stream.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)).filter(java.util.Objects::nonNull).toList();
			assertThat(results).hasSize(1);
			assertThat(stored(results.getFirst()).version()).isEqualTo(1);
			assertThat(exchange(request(results.getFirst(), authenticatedClient(results.getFirst()))).getAccessToken()).isNotNull();
		}
		assertThat(protocolAudits()).filteredOn(row -> row.get("action").equals("authorization_code_issued")).hasSize(1);
		assertThat(protocolAudits()).filteredOn(row -> row.get("action").equals("authorization_request_rejected")).hasSize(1);
		assertThat(this.interactions.find(this.owner, ticket.handle())).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = {"delete-suppressed", "delete-deferred", "success-audit-suppressed", "success-audit-deferred", "binding-suppressed"})
	void failedConsumptionBindingOrMandatoryAuditRollsBackTheCodeAndLeavesTheRequestPending(String failure) {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner);
		switch (failure) {
			case "delete-suppressed" -> resumptionFault("iam_authorization_interaction", "BEFORE DELETE", "RETURN NULL;", false);
			case "delete-deferred" -> resumptionFault("iam_authorization_interaction", "AFTER DELETE", "RAISE EXCEPTION 'isolated resumption commit failure';", true);
			case "success-audit-suppressed" -> resumptionFault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "success-audit-deferred" -> resumptionFault("iam_security_audit", "AFTER INSERT", "IF NEW.action='authorization_code_issued' THEN RAISE EXCEPTION 'isolated resumption audit failure'; END IF; RETURN NEW;", true);
			default -> resumptionFault("iam_authorization_binding", "BEFORE INSERT", "RETURN NULL;", false);
		}
		rejection(() -> resume(ticket), "server_error");
		assertNoGrants(); assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
		assertThat(protocolAudits()).singleElement().satisfies(row -> assertThat(row.get("action")).isEqualTo("authorization_request_rejected"));
	}

	@Test
	void expiryDuringConsumptionRollsBackTheSuccessfulCodeAndItsAudit() {
		var ticket = expiringInteraction(1);
		resumptionFault("iam_authorization_interaction", "BEFORE DELETE", "PERFORM pg_sleep(1.2); RETURN OLD;", false);
		rejection(() -> resume(ticket), "invalid_request"); assertNoGrants();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isEqualTo(1);
		assertThat(protocolAudits()).singleElement().satisfies(row -> assertThat(row.get("action")).isEqualTo("authorization_request_rejected"));
	}

	@Test
	void aRequestThatExpiresWhileWaitingForTheSubjectCannotProduceACode() throws Exception {
		var ticket = expiringInteraction(2); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
				this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single(); locked.countDown(); awaitLatch(release);
			}));
			awaitLatch(locked);
			var resumed = executor.submit(() -> { serverContext("https://iam.example"); return rejection(() -> resume(ticket), "invalid_request"); });
			try {
				await().atMost(5, TimeUnit.SECONDS).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock')").query(Boolean.class).single());
				await().atMost(5, TimeUnit.SECONDS).until(() -> !this.interactionRepository.now().isBefore(ticket.interaction().expiresAt()));
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS); resumed.get(10, TimeUnit.SECONDS);
		}
		assertNoGrants();
	}

	@Test
	void failedDenialAuditNeverConvertsARejectedResumptionIntoSuccess() {
		var ticket = this.interactive.begin(request(Map.of("prompt", "login")), this.owner);
		resumptionFault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_request_rejected' THEN RETURN NULL; END IF; RETURN NEW;", false);
		rejection(() -> resume(ticket), "server_error"); assertNoGrants();
		assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent(); assertThat(protocolAudits()).isEmpty();
	}

	@Test
	void authenticationAgeIsRecheckedAfterTheSuccessAuditAndConsumption() {
		var ticket = this.interactive.begin(request(Map.of("max_age", "1")), this.owner); freshLogin(ticket);
		resumptionFault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_code_issued' THEN PERFORM pg_sleep(1.2); END IF; RETURN NEW;", false);
		rejection(() -> resume(ticket), "login_required"); assertNoGrants();
		assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
		assertThat(protocolAudits()).singleElement().satisfies(row -> assertThat(row.get("action")).isEqualTo("authorization_request_rejected"));
	}

	@Test
	void sourceSessionExpiryDuringConsumptionCannotPublishAnAlreadyExpiredCode() {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner);
		this.jdbc.sql("UPDATE iam_browser_session SET expiry_time=(extract(epoch FROM clock_timestamp())*1000)::bigint+2000 WHERE session_id=:id").param("id", this.sessionId).update();
		this.jdbc.sql("CREATE SEQUENCE resumption_test_probe").update();
		resumptionFault("iam_authorization_interaction", "BEFORE DELETE", "PERFORM nextval('resumption_test_probe'); PERFORM pg_sleep(2.2); RETURN OLD;", false);
		rejection(() -> resume(ticket), "login_required"); assertNoGrants();
		assertThat(this.jdbc.sql("SELECT is_called FROM resumption_test_probe").query(Boolean.class).single()).isTrue();
		assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
	}

	@Test
	void anAmbientTransactionIsRejectedBeforeAnyIndependentAuditCanWaitForItsOwnSubjectLock() {
		var ticket = this.interactive.begin(request(Map.of("prompt", "consent")), this.owner);
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> {
			this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
			rejection(() -> resume(ticket), "server_error"); rejection(() -> this.interactive.begin(request(Map.of()), this.owner), "server_error");
		});
		assertNoGrants(); assertThat(protocolAudits()).isEmpty(); assertThat(this.interactions.find(this.owner, ticket.handle())).isPresent();
	}

	@Test
	void aFullBrowserInteractionQueueReturnsAFixedAuditedTemporaryFailure() {
		for (int i = 0; i < 8; i++) { this.interactive.begin(request(Map.of("prompt", "consent")), this.owner); }
		rejection(() -> this.interactive.begin(request(Map.of("prompt", "consent")), this.owner), "temporarily_unavailable");
		assertNoGrants(); assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction").query(Long.class).single()).isEqualTo(8);
		assertThat(protocolAudits()).singleElement().satisfies(row -> assertThat(row.get("action")).isEqualTo("authorization_request_rejected"));
	}

	private OAuth2AuthorizationCodeRequestAuthenticationToken request(Map<String, Object> extras) {
		var parameters = new HashMap<String, Object>(); parameters.put("code_challenge", CHALLENGE); parameters.put("code_challenge_method", "S256"); parameters.put("nonce", NONCE); parameters.putAll(extras);
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", this.clientId.toString(), browser(), REDIRECT,
				"resumption-client-state", Set.of("openid", "profile", "offline_access"), parameters);
		request.setDetails(evidence()); return request;
	}
	private Authentication browser() { return UsernamePasswordAuthenticationToken.authenticated(this.userId, "browser-secret", List.of(new SimpleGrantedAuthority("ROLE_IAM_ADMIN"))); }
	private IdentityAuthorizationRequestProvider.BrowserEvidence evidence() { return new IdentityAuthorizationRequestProvider.BrowserEvidence(this.sessionId, this.authenticatedAt, 1, UUID.randomUUID()); }
	private OAuth2AuthorizationCodeRequestAuthenticationToken resume(IdentityAuthorizationInteractions.Ticket ticket) { return this.interactive.resume(this.owner, ticket.handle(), browser(), evidence()); }
	private void freshLogin(IdentityAuthorizationInteractions.Ticket ticket) {
		await().atMost(3, TimeUnit.SECONDS).until(() -> Instant.ofEpochMilli(System.currentTimeMillis()).isAfter(ticket.interaction().createdAt()));
		var session = this.store.findById(this.sessionId); session.changeSessionId(); this.authenticatedAt = System.currentTimeMillis();
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, this.authenticatedAt); this.store.save(session); this.sessionId = session.getId();
	}
	private OAuth2AuthorizationCodeRequestAuthenticationException rejection(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, String code) {
		var failure = catchThrowableOfType(OAuth2AuthorizationCodeRequestAuthenticationException.class, action);
		assertThat(failure).isNotNull(); assertThat(failure.getError().getErrorCode()).isEqualTo(code); assertThat(failure.getCause()).isNull();
		assertThat(failure.getMessage()).doesNotContain(this.owner, this.secret, "resumption-client-state", NONCE, CHALLENGE, this.sessionId, "isolated resumption"); return failure;
	}
	private void assertNoGrants() {
		for (String table : List.of("oauth2_authorization", "iam_authorization_binding", "iam_authorization_binding_role", "iam_refresh_family")) {
			assertThat(this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single()).as(table).isZero();
		}
	}
	private List<Map<String, Object>> protocolAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('authorization_code_issued','authorization_request_rejected') ORDER BY recorded_at,id").query().listOfRows(); }
	private String resumeAfter(CountDownLatch begin, IdentityAuthorizationInteractions.Ticket ticket) {
		serverContext("https://iam.example"); awaitLatch(begin);
		try { return resume(ticket).getAuthorizationCode().getTokenValue(); }
		catch (OAuth2AuthorizationCodeRequestAuthenticationException ex) { assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_request"); return null; }
	}
	private IdentityAuthorizationInteractions.Ticket expiringInteraction(int secondsRemaining) {
		var normalized = request(Map.of("prompt", "consent")); var parameters = new HashMap<String, String>(); normalized.getAdditionalParameters().forEach((key, value) -> parameters.put(key, (String) value));
		var original = new IdentityAuthorizationInteraction.Request(normalized.getAuthorizationUri(), this.clientId, REDIRECT, normalized.getState(), normalized.getScopes(), parameters);
		var expiry = this.interactionRepository.now().truncatedTo(ChronoUnit.MICROS).plusSeconds(secondsRemaining);
		var pending = new IdentityAuthorizationInteraction(UUID.randomUUID(), original, 0, expiry.minusSeconds(600), expiry); String handle = this.interactions.newBrowserOwner();
		new TransactionTemplate(this.transactions).executeWithoutResult(status -> this.interactionRepository.insert(new StoredInteraction(pending, this.secrets.interactionDigest(handle), this.secrets.interactionOwnerDigest(this.owner))));
		return new IdentityAuthorizationInteractions.Ticket(handle, pending);
	}
	private void resumptionFault(String table, String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION resumption_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").update();
		this.jdbc.sql("CREATE " + (deferred ? "CONSTRAINT " : "") + "TRIGGER resumption_test_fault " + timing + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION resumption_test_fault()").update();
	}

}
