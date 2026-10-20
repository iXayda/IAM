package com.ixayda.iam.security;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityAuthorizationSession;
import com.ixayda.iam.model.IdentityRefreshFamily;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityRefreshTokenProviderIntegrationTests extends IdentityProtocolTestSupport {

	private IdentityRefreshTokenProvider refreshProvider;

	@BeforeEach
	void createRefreshProvider() {
		this.refreshProvider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
	}

	@Test
	void nativeRefreshRotatesOneSuccessorAndCommitsProtectedStateHistoryAndAuditBeforeResponding() throws Exception {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var before = stored(code);
		String parent = initial.getRefreshToken().getTokenValue(); var request = refreshRequest(parent, Set.of());
		var response = rotate(request); var after = stored(code);
		assertThat(after.version()).isEqualTo(before.version() + 1);
		assertThat(response.getRefreshToken().getTokenValue()).isNotEqualTo(parent);
		assertThat(after.authorization().getAccessToken().getToken()).isEqualTo(response.getAccessToken());
		assertThat(after.authorization().getRefreshToken().getToken()).isEqualTo(response.getRefreshToken());
		assertThat(after.authorization().getToken(OidcIdToken.class).getToken().getTokenValue()).isEqualTo(response.getAdditionalParameters().get("id_token"));
		var old = this.refresh.findByToken(parent).orElseThrow(); var child = this.refresh.findByToken(response.getRefreshToken().getTokenValue()).orElseThrow();
		var family = this.refresh.findByAuthorization(after.authorization()).orElseThrow();
		assertThat(old.consumedAt()).isEqualTo(child.issuedAt()); assertThat(child.parentDigest()).isEqualTo(old.digest());
		assertThat(child.generation()).isEqualTo(1); assertThat(child.consumedAt()).isNull();
		assertThat(family.generation()).isEqualTo(1); assertThat(family.version()).isEqualTo(2); assertThat(family.currentDigest()).isEqualTo(child.digest());
		assertThat(family.scopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
		assertThat(family.absoluteExpiresAt()).isEqualTo(this.bindings.findByAuthorization(after.authorization()).orElseThrow().issuedAt().plus(30, ChronoUnit.DAYS));
		assertThat(family.startedAt()).isEqualTo(initial.getRefreshToken().getIssuedAt());
		assertThat(Duration.between(child.issuedAt(), child.expiresAt())).isEqualTo(Duration.ofDays(7));
		assertThat(this.authorizations.findByToken(parent, "refresh_token")).isEmpty();
		var access = verified(response.getAccessToken().getTokenValue(), "at+jwt");
		assertThat(access.getAudience()).containsExactly("urn:example:orders"); assertThat(access.getStringListClaim("roles")).containsExactly("reader");
		assertThat(access.getStringClaim("scope")).isEqualTo("offline_access openid profile");
		assertThat(Duration.between(access.getIssueTime().toInstant(), access.getExpirationTime().toInstant())).isEqualTo(Duration.ofSeconds(300));
		var id = verified((String) response.getAdditionalParameters().get("id_token"), "JWT");
		assertThat(id.getAudience()).containsExactly(this.clientId.toString());
		assertThat(id.getDateClaim("auth_time").toInstant()).isEqualTo(Instant.ofEpochMilli(this.authenticatedAt).truncatedTo(ChronoUnit.SECONDS));
		assertThat(id.getClaims()).doesNotContainKeys("roles", "scope", "sid");
		assertThat(refreshAudits()).singleElement().satisfies(audit -> {
			assertThat(audit.get("action")).isEqualTo("tokens_refreshed"); assertThat(audit.get("outcome")).isEqualTo("success");
			assertThat(audit.get("actor")).isEqualTo("client:" + this.clientId); assertThat(audit.get("target_user_id")).isEqualTo(this.userId);
			assertThat(audit.get("correlation_id")).isEqualTo(((IdentityRefreshTokenProvider.RequestEvidence) request.getDetails()).correlationId());
		});
		assertThat(this.context.getBeansOfType(IdentityRefreshTokenProvider.class)).isEmpty();
		assertThat(after.authorization().getAttributes().toString()).doesNotContain(this.secret, this.sessionId, "ROLE_IAM_ADMIN");
	}

	@Test
	void consumedRefreshReplaysCommitFamilyQuarantineAndRevokeTheNewSuccessor() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		String parent = initial.getRefreshToken().getTokenValue(); var successor = rotate(refreshRequest(parent, Set.of()));
		refreshRejection(refreshRequest(parent, Set.of()), "invalid_grant"); assertRevoked(code);
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().extracting(IdentityRefreshFamily::status).isEqualTo(IdentityRefreshFamily.Status.QUARANTINED);
		refreshRejection(refreshRequest(successor.getRefreshToken().getTokenValue(), Set.of()), "invalid_grant");
		assertThat(refreshAudits()).extracting(audit -> audit.get("action")).containsExactly("tokens_refreshed", "refresh_token_replayed", "token_request_rejected");
	}

	@Test
	void browserSessionDeletionDoesNotEndTheIndependentOfflineGrant() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		this.store.deleteById(this.sessionId);
		assertThat(rotate(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of())).getRefreshToken()).isNotNull();
	}

	@Test
	void scopeReductionPersistsAcrossOmittedScopeAndCannotReexpandTheOriginalGrant() throws Exception {
		String code = offlineCode(); var first = exchange(request(code, authenticatedClient(code)));
		var reduced = rotate(refreshRequest(first.getRefreshToken().getTokenValue(), Set.of("openid", "offline_access")));
		assertThat(reduced.getAccessToken().getScopes()).containsExactlyInAnyOrder("openid", "offline_access");
		var omitted = rotate(refreshRequest(reduced.getRefreshToken().getTokenValue(), Set.of()));
		assertThat(verified(omitted.getAccessToken().getTokenValue(), "at+jwt").getStringClaim("scope")).isEqualTo("offline_access openid");
		assertThat(stored(code).authorization().getAuthorizedScopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
		assertThat(this.bindings.findByAuthorization(stored(code).authorization())).get().satisfies(binding -> assertThat(binding.scopes()).contains("profile"));
		var before = stored(code); var family = this.refresh.findByAuthorization(before.authorization()).orElseThrow();
		for (String expansion : List.of("profile", "other")) {
			refreshRejection(refreshRequest(omitted.getRefreshToken().getTokenValue(), Set.of("openid", "offline_access", expansion)), "invalid_scope");
		}
		assertThat(stored(code)).isEqualTo(before); assertThat(this.refresh.findByAuthorization(stored(code).authorization())).contains(family);
		assertThat(this.refresh.findByToken(omitted.getRefreshToken().getTokenValue())).get().satisfies(history -> assertThat(history.consumedAt()).isNull());
		assertThat(rotate(refreshRequest(omitted.getRefreshToken().getTokenValue(), Set.of())).getAccessToken().getScopes()).containsExactlyInAnyOrder("openid", "offline_access");
	}

	@Test
	void removingOpenidAllowsConsecutiveOfflineRefreshesWithoutReturningOrRenewingTheHistoricalId() throws Exception {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		var historical = stored(code).authorization().getToken(OidcIdToken.class); var response = initial;
		for (int generation = 1; generation <= 3; generation++) {
			response = rotate(refreshRequest(response.getRefreshToken().getTokenValue(), generation == 1 ? Set.of("profile", "offline_access") : Set.of()));
			assertThat(response.getAdditionalParameters()).isEmpty(); assertThat(response.getAccessToken().getScopes()).containsExactlyInAnyOrder("profile", "offline_access");
			assertThat(stored(code).authorization().getToken(OidcIdToken.class)).isEqualTo(historical);
			assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().extracting(IdentityRefreshFamily::generation).isEqualTo((long) generation);
		}
		refreshRejection(refreshRequest(response.getRefreshToken().getTokenValue(), Set.of("openid", "profile", "offline_access")), "invalid_scope");
	}

	@ParameterizedTest
	@ValueSource(strings = { "openid", "profile" })
	void removingOfflineAccessClosesTheFamilyOmitsTheSuccessorAndAllowsReplayQuarantineOfFinalAccess(String remaining) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		String parent = initial.getRefreshToken().getTokenValue(); var response = rotate(refreshRequest(parent, Set.of(remaining)));
		assertThat(response.getRefreshToken()).isNull(); assertThat(stored(code).authorization().getRefreshToken()).isNull();
		assertThat(response.getAccessToken().getScopes()).containsExactly(remaining);
		assertThat(response.getAdditionalParameters().containsKey("id_token")).isEqualTo(remaining.equals("openid"));
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_token_index WHERE token_type='refresh_token'").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isEqualTo(2);
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().satisfies(family -> {
			assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.CLOSED); assertThat(family.generation()).isEqualTo(1); assertThat(family.scopes()).containsExactly(remaining);
		});
		refreshRejection(refreshRequest(parent, Set.of()), "invalid_grant");
		assertThat(stored(code).authorization().getAccessToken().isInvalidated()).isTrue();
		assertThat(stored(code).authorization().getToken(OidcIdToken.class).isInvalidated()).isTrue();
	}

	@Test
	void simultaneousUseOfOneParentHasOneSuccessorAndTheLosingReplayCommitsItsQuarantine() throws Exception {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()); var start = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			var first = executor.submit(() -> concurrentRefresh(request, start)); var second = executor.submit(() -> concurrentRefresh(request, start));
			start.countDown(); assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS))).containsExactlyInAnyOrder("success", "invalid_grant");
		}
		assertRevoked(code); assertThat(stored(code).version()).isEqualTo(4);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isEqualTo(2);
		assertThat(refreshAudits()).extracting(audit -> audit.get("action")).containsExactly("tokens_refreshed", "refresh_token_replayed");
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void anotherAuthenticatedClientCannotRedeemOrQuarantineTheOwnersCurrentOrSpentToken(boolean consumed) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getRefreshToken().getTokenValue();
		if (consumed) { rotate(refreshRequest(token, Set.of())); }
		var before = stored(code); var family = this.refresh.findByAuthorization(before.authorization()).orElseThrow();
		var foreign = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		refreshRejection(refreshRequest(token, Set.of(), refreshClient(foreign.client().id(), foreign.secret())), "invalid_grant");
		assertThat(stored(code)).isEqualTo(before); assertThat(this.refresh.findByAuthorization(stored(code).authorization())).contains(family);
		assertThat(refreshAudits().getLast().get("target_user_id")).isNull();
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-disabled", "credential", "client-secret", "client-disabled", "client-transferred", "resource", "resource-disabled", "role", "role-disabled", "assignment" })
	void currentUserClientCredentialResourceAndCompleteRolesMustStillMatchTheOriginalGrant(String mutation) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of());
		var before = stored(code); mutate(mutation);
		refreshRejection(request, "invalid_grant"); assertUnrotated(code, before.version(), initial.getRefreshToken().getTokenValue());
	}

	@Test
	void aNewRoleAssignmentCannotSilentlyExpandAnExistingGrant() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		var role = this.roles.create(this.resourceId, "writer", "Writer", AUDIT); this.assignments.change(this.userId, role.id(), 1, true, AUDIT);
		refreshRejection(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()), "invalid_grant");
		assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
	}

	@Test
	void aSecretChangedWhileWaitingForTheUserLockInvalidatesTheEarlierClientProof() throws Exception {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of());
		var locked = new CountDownLatch(1); var change = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
					locked.countDown(); awaitLatch(change); this.clients.rotateSecret(this.clientId, 1, AUDIT);
				}));
				awaitLatch(locked);
				var reader = executor.submit(() -> { serverContext("https://iam.example"); try { return refreshRejection(request, "invalid_grant"); } finally { AuthorizationServerContextHolder.resetContext(); } });
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR SHARE%')").query(Boolean.class).single());
				change.countDown(); writer.get(10, TimeUnit.SECONDS); assertThat(reader.get(10, TimeUnit.SECONDS)).isNotNull();
				assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
			}
			finally { change.countDown(); }
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "native-suppressed", "native-altered", "revision-suppressed", "index-suppressed", "audit-suppressed", "audit-altered", "audit-unavailable", "deferred", "family-suppressed", "family-altered", "history-suppressed", "history-altered", "consumption-suppressed", "consumption-altered", "family-deferred", "history-deferred" })
	void aPartialWriteAuditFailureOrDeferredFailureCannotConsumeTheParentOrPublishItsSuccessor(String failure) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of());
		switch (failure) {
			case "native-suppressed" -> fault("oauth2_authorization", "BEFORE UPDATE", "RETURN NULL;", false);
			case "native-altered" -> fault("oauth2_authorization", "BEFORE UPDATE", "NEW.id_token_value=NULL; RETURN NEW;", false);
			case "revision-suppressed" -> fault("iam_authorization_record", "BEFORE UPDATE", "RETURN NULL;", false);
			case "index-suppressed" -> fault("iam_authorization_token_index", "BEFORE INSERT", "IF NEW.token_type='refresh_token' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-suppressed" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_refreshed' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-altered" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_refreshed' THEN NEW.actor='anonymous'; END IF; RETURN NEW;", false);
			case "audit-unavailable" -> fault("iam_security_audit", "BEFORE INSERT", "RAISE EXCEPTION 'isolated exchange audit fault';", false);
			case "family-suppressed" -> fault("iam_refresh_family", "BEFORE UPDATE", "RETURN NULL;", false);
			case "family-altered" -> fault("iam_refresh_family", "BEFORE UPDATE", "NEW.updated_at=NEW.updated_at+INTERVAL '1 microsecond'; RETURN NEW;", false);
			case "history-suppressed" -> fault("iam_refresh_history", "BEFORE INSERT", "RETURN NULL;", false);
			case "history-altered" -> fault("iam_refresh_history", "BEFORE INSERT", "NEW.expires_at=NEW.expires_at-INTERVAL '1 second'; RETURN NEW;", false);
			case "consumption-suppressed" -> fault("iam_refresh_history", "BEFORE UPDATE", "RETURN NULL;", false);
			case "consumption-altered" -> fault("iam_refresh_history", "BEFORE UPDATE", "NEW.consumed_at=NEW.consumed_at+INTERVAL '1 microsecond'; RETURN NEW;", false);
			case "family-deferred" -> fault("iam_refresh_family", "AFTER UPDATE", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
			case "history-deferred" -> fault("iam_refresh_history", "AFTER INSERT", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
			default -> fault("oauth2_authorization", "AFTER UPDATE", "RAISE EXCEPTION 'isolated exchange commit fault';", true);
		}
		refreshRejection(request, "server_error"); assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
		assertThat(refreshAudits()).hasSize(failure.equals("audit-unavailable") ? 0 : 1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "suppressed", "altered", "deferred", "family" })
	void replayQuarantineAndFailureAuditRollbackTogetherAndAValidRetryCommitsTheDecision(String failure) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getRefreshToken().getTokenValue();
		rotate(refreshRequest(token, Set.of()));
		switch (failure) {
			case "suppressed" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='refresh_token_replayed' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "altered" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='refresh_token_replayed' THEN NEW.actor='anonymous'; END IF; RETURN NEW;", false);
			case "deferred" -> fault("iam_security_audit", "AFTER INSERT", "IF NEW.action='refresh_token_replayed' THEN RAISE EXCEPTION 'isolated exchange replay fault'; END IF; RETURN NEW;", true);
			default -> fault("iam_refresh_family", "BEFORE UPDATE", "RETURN NULL;", false);
		}
		refreshRejection(refreshRequest(token, Set.of()), "server_error");
		assertThat(stored(code).version()).isEqualTo(3); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON " + (failure.equals("family") ? "iam_refresh_family" : "iam_security_audit")).update();
		refreshRejection(refreshRequest(token, Set.of()), "invalid_grant"); assertRevoked(code);
	}

	@Test
	void parentExpiryDuringMandatoryAuditRollsBackRotationAndItsSpentTransition() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getRefreshToken().getTokenValue();
		shortenInitialRefresh(code, Instant.now().plusMillis(900));
		this.jdbc.sql("CREATE SEQUENCE exchange_test_audit_probe").update();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='tokens_refreshed' THEN PERFORM nextval('exchange_test_audit_probe'); PERFORM pg_sleep(1.2); END IF; RETURN NEW;", false);
		refreshRejection(refreshRequest(token, Set.of()), "invalid_grant"); assertUnrotated(code, 3, token);
		assertThat(this.jdbc.sql("SELECT is_called FROM exchange_test_audit_probe").query(Boolean.class).single()).isTrue();
	}

	@ParameterizedTest
	@ValueSource(strings = { "missing", "other", "http" })
	void refreshingRequiresTheSameExplicitHttpsIssuerAsTheOriginalRequest(String invalid) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of());
		if (invalid.equals("missing")) { AuthorizationServerContextHolder.resetContext(); }
		else { serverContext(invalid.equals("http") ? "http://iam.example" : "https://other.example"); }
		refreshRejection(request, invalid.equals("other") ? "invalid_grant" : "server_error"); assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
	}

	@Test
	void unknownRefreshAndUnauthenticatedClientAreRejectedWithoutNamingAnotherSubject() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		refreshRejection(refreshRequest("unknown-refresh-token", Set.of()), "invalid_grant");
		refreshRejection(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of(), UsernamePasswordAuthenticationToken.unauthenticated("ignored", null)), "invalid_client");
		assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue()); assertThat(refreshAudits()).allSatisfy(audit -> assertThat(audit.get("target_user_id")).isNull());
	}

	@Test
	void ambientTransactionsCannotReceiveTokensBeforeCommitAndOtherAuthenticationTypesAreIgnored() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var request = refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of());
		assertThat(this.refreshProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("ignored", null))).isNull();
		assertThat(this.refreshProvider.supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue(); assertThat(this.refreshProvider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> refreshRejection(request, "server_error")); assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
	}

	@Test
	void aConsumedAuthorizationCodeReplayQuarantinesTheEntireRotatedRefreshFamily() {
		String code = offlineCode(); var original = request(code, authenticatedClient(code)); var initial = exchange(original);
		var first = rotate(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()));
		rotate(refreshRequest(first.getRefreshToken().getTokenValue(), Set.of()));
		rejection(original, "invalid_grant"); assertRevoked(code);
		assertThat(this.refresh.findByAuthorization(stored(code).authorization())).get().extracting(IdentityRefreshFamily::status).isEqualTo(IdentityRefreshFamily.Status.QUARANTINED);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history WHERE consumed_at IS NOT NULL").query(Long.class).single()).isEqualTo(2);
	}

	@Test
	void replayDoesNotRevokeAnotherAuthorizationForTheSameUserAndClient() {
		String code = offlineCode(); String otherCode = offlineCode();
		var initial = exchange(request(code, authenticatedClient(code))); var other = exchange(request(otherCode, authenticatedClient(otherCode)));
		rotate(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()));
		refreshRejection(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()), "invalid_grant"); assertRevoked(code);
		assertThat(stored(otherCode).authorization().getAccessToken().isActive()).isTrue();
		assertThat(rotate(refreshRequest(other.getRefreshToken().getTokenValue(), Set.of())).getRefreshToken()).isNotNull();
	}

	@Test
	void consumedHistoryStillDetectsReplayAfterTheParentsIndividualExpiry() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String parent = initial.getRefreshToken().getTokenValue();
		Instant expiry = Instant.now().plusMillis(800); shortenInitialRefresh(code, expiry); rotate(refreshRequest(parent, Set.of()));
		await().atMost(Duration.ofSeconds(3)).until(() -> Instant.now().isAfter(expiry));
		refreshRejection(refreshRequest(parent, Set.of()), "invalid_grant"); assertRevoked(code);
		assertThat(this.refresh.findByToken(parent)).get().satisfies(history -> assertThat(history.consumedAt()).isNotNull());
	}

	@Test
	void anExpiredUnusedRefreshCannotBeRotatedOrMisclassifiedAsReplay() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String parent = initial.getRefreshToken().getTokenValue();
		Instant expiry = Instant.now().plusMillis(150); shortenInitialRefresh(code, expiry);
		await().atMost(Duration.ofSeconds(3)).until(() -> Instant.now().isAfter(expiry));
		refreshRejection(refreshRequest(parent, Set.of()), "invalid_grant"); assertUnrotated(code, 3, parent);
		assertThat(refreshAudits()).extracting(audit -> audit.get("action")).containsExactly("token_request_rejected");
	}

	@ParameterizedTest
	@ValueSource(strings = { "access", "id", "code" })
	void otherCredentialPurposesCannotBeUsedAsRefreshTokens(String purpose) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		String value = switch (purpose) { case "access" -> initial.getAccessToken().getTokenValue(); case "id" -> (String) initial.getAdditionalParameters().get("id_token"); default -> code; };
		refreshRejection(refreshRequest(value, Set.of()), "invalid_grant"); assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
	}

	@ParameterizedTest
	@ValueSource(strings = { "scope", "resource", "audience", "request", "request_uri", "object" })
	void unsupportedNonemptyExtensionsAndNonStringParametersCannotChangeARefreshRequest(String parameter) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String parent = initial.getRefreshToken().getTokenValue();
		var request = new OAuth2RefreshTokenAuthenticationToken(parent, refreshClient(this.clientId, this.secret), Set.of(),
				Map.of(parameter, parameter.equals("object") ? new String[] { "untrusted" } : "untrusted"));
		refreshRejection(request, "invalid_request"); assertUnrotated(code, 2, parent);
	}

	@Test
	void ignoredStringExtensionsAndEmptyOptionalExtensionsAreNotPersistedOrReturned() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); String parent = initial.getRefreshToken().getTokenValue();
		var request = new OAuth2RefreshTokenAuthenticationToken(parent, refreshClient(this.clientId, this.secret), Set.of(), Map.of("unknown-extension", "ignored-extension-value", "resource", "", "request_uri", ""));
		var response = rotate(request);
		assertThat(response.getAdditionalParameters()).containsOnlyKeys("id_token");
		assertThat(stored(code).authorization().getAttributes().toString()).doesNotContain("ignored-extension-value", "unknown-extension");
	}

	@ParameterizedTest
	@ValueSource(strings = { "raw-secret", "unverified", "wrong-method", "no-snapshot" })
	void aClientMustHaveTheExactAuthenticatedBasicSnapshotAndNoRawCredentials(String invalid) {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code))); var valid = refreshClient(this.clientId, this.secret);
		var client = switch (invalid) {
			case "raw-secret" -> new OAuth2ClientAuthenticationToken(valid.getRegisteredClient(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.secret);
			case "unverified" -> new OAuth2ClientAuthenticationToken(this.clientId.toString(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.secret, Map.of());
			case "wrong-method" -> new OAuth2ClientAuthenticationToken(valid.getRegisteredClient(), ClientAuthenticationMethod.CLIENT_SECRET_POST, null);
			default -> new OAuth2ClientAuthenticationToken(valid.getRegisteredClient(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		};
		if (!invalid.equals("no-snapshot")) { client.setDetails(valid.getDetails()); }
		refreshRejection(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of(), client), "invalid_client"); assertUnrotated(code, 2, initial.getRefreshToken().getTokenValue());
	}

	@Test
	void aChangedHistorySealCannotAuthorizeRotationOrInventAReplayDecision() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		this.jdbc.sql("UPDATE iam_refresh_history SET consumed_at=clock_timestamp(),seal=:seal").param("seal", "0".repeat(64)).update();
		refreshRejection(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of()), "server_error");
		assertThat(stored(code).version()).isEqualTo(2); assertThat(stored(code).authorization().getAccessToken().isActive()).isTrue();
		assertThat(refreshAudits()).extracting(audit -> audit.get("action")).containsExactly("token_request_rejected");
	}

	@Test
	void freshProviderInstancesResumeThePersistentFamilyWithoutRequestThreadState() {
		String code = offlineCode(); var initial = exchange(request(code, authenticatedClient(code)));
		var first = rotate(refreshRequest(initial.getRefreshToken().getTokenValue(), Set.of())); createRefreshProvider();
		var next = rotate(refreshRequest(first.getRefreshToken().getTokenValue(), Set.of()));
		assertThat(this.refresh.findByToken(next.getRefreshToken().getTokenValue())).get().extracting(history -> history.generation()).isEqualTo(2L);
	}

	@Test
	void officialGeneratorsCapAllTokenPurposesAtTheOriginalThirtyDayDeadlineEvenAfterTheOriginalCodeAndBrowserExpired() {
		String code = offlineCode(); exchange(request(code, authenticatedClient(code))); var original = this.bindings.findByAuthorization(stored(code).authorization()).orElseThrow();
		Instant deadline = Instant.now().plusSeconds(45).truncatedTo(ChronoUnit.SECONDS); Instant agedIssuance = deadline.minus(30, ChronoUnit.DAYS);
		var source = original.session(); var agedSession = new IdentityAuthorizationSession(source.access(), source.browserSessionId(), agedIssuance.minusSeconds(2), agedIssuance.plusSeconds(1800), agedIssuance.plusSeconds(28800));
		var aged = new IdentityAuthorizationBinding(original.id(), agedSession, original.scopes(), agedIssuance, agedIssuance.plusSeconds(60));
		var client = this.protocol.findActiveById(this.clientId.toString()).orElseThrow();
		var generator = new IdentityTokenGenerator(new IdentityJwtEncoder(this.keys), aged, client, "https://iam.example");
		for (OAuth2TokenType type : List.of(OAuth2TokenType.ACCESS_TOKEN, OAuth2TokenType.REFRESH_TOKEN, new OAuth2TokenType("id_token"))) {
			OAuth2Token generated = new TransactionTemplate(this.transactions).execute(tx -> generator.generate(DefaultOAuth2TokenContext.builder()
					.registeredClient(client.registration()).principal(this.bindings.projectPrincipal(agedSession)).authorization(stored(code).authorization())
					.authorizationServerContext(AuthorizationServerContextHolder.getContext()).authorizedScopes(original.scopes())
					.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).authorizationGrant(refreshRequest("test-grant-context", Set.of()))
					.tokenType(type).build()));
			assertThat(generated).isNotNull(); assertThat(generated.getExpiresAt()).isEqualTo(deadline);
		}
	}

	private String offlineCode() { return code(Set.of("openid", "profile", "offline_access")); }
	private void assertUnrotated(String code, long version, String parent) {
		assertThat(stored(code).version()).isEqualTo(version); assertThat(stored(code).authorization().getRefreshToken().getToken().getTokenValue()).isEqualTo(parent);
		assertThat(this.refresh.findByToken(parent)).get().satisfies(history -> assertThat(history.consumedAt()).isNull());
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isEqualTo(1);
	}
	private String concurrentRefresh(OAuth2RefreshTokenAuthenticationToken request, CountDownLatch start) {
		awaitLatch(start); serverContext("https://iam.example");
		try { rotate(request); return "success"; }
		catch (OAuth2AuthenticationException ex) { return ex.getError().getErrorCode(); }
		finally { AuthorizationServerContextHolder.resetContext(); }
	}
	private void shortenInitialRefresh(String code, Instant expiry) {
		var current = stored(code); var token = current.authorization().getRefreshToken().getToken();
		// Recreate only this isolated fixture's initial family through the production initializer, with a short actual lifetime.
		this.jdbc.sql("TRUNCATE iam_refresh_family CASCADE").update();
		var shortLived = OAuth2Authorization.from(current.authorization()).refreshToken(new OAuth2RefreshToken(token.getTokenValue(), token.getIssuedAt(), expiry.truncatedTo(ChronoUnit.MICROS)))
				.attributes(values -> values.remove("iam.refreshFamily")).build();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> this.refresh.initialize(shortLived, current.version(), this.bindings.findByAuthorization(current.authorization()).orElseThrow()));
	}
	private OAuth2RefreshTokenAuthenticationToken refreshRequest(String token, Set<String> scopes) { return refreshRequest(token, scopes, refreshClient(this.clientId, this.secret)); }
	private OAuth2RefreshTokenAuthenticationToken refreshRequest(String token, Set<String> scopes, Authentication client) {
		var request = new OAuth2RefreshTokenAuthenticationToken(token, client, scopes, Map.of());
		request.setDetails(new IdentityRefreshTokenProvider.RequestEvidence(UUID.randomUUID())); return request;
	}

	private OAuth2AccessTokenAuthenticationToken rotate(OAuth2RefreshTokenAuthenticationToken request) { return (OAuth2AccessTokenAuthenticationToken) this.refreshProvider.authenticate(request); }
	private OAuth2AuthenticationException refreshRejection(OAuth2RefreshTokenAuthenticationToken request, String code) {
		var exception = catchThrowableOfType(OAuth2AuthenticationException.class, () -> this.refreshProvider.authenticate(request));
		assertThat(exception).isNotNull(); assertThat(exception.getError().getErrorCode()).isEqualTo(code); assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).doesNotContain(request.getRefreshToken(), this.secret, this.sessionId, "isolated exchange"); return exception;
	}
	private List<Map<String, Object>> refreshAudits() {
		return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action IN ('tokens_refreshed','refresh_token_replayed','token_request_rejected') ORDER BY recorded_at,id").query().listOfRows();
	}

}
