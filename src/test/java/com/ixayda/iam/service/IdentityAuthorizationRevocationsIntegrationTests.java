package com.ixayda.iam.service;

import java.sql.Types;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.security.IdentityAuthorizationRequestProvider;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityAuthorizationRevocationsIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentityAuthorizationRevocations revocations;
	@Autowired private IdentityAccessTokens online;

	@ParameterizedTest
	@ValueSource(strings = { "code", "ordinary", "offline", "closed", "quarantined" })
	void revocationAtomicallyInvalidatesEveryNativeCredentialAndPreservesOriginalBoundsAndRefreshHistory(String stage) {
		boolean offline = !stage.equals("ordinary");
		String code = code(offline ? Set.of("openid", "profile", "offline_access") : Set.of("openid", "profile"));
		if (!stage.equals("code")) {
			var initial = exchange(request(code, authenticatedClient(code)));
			if (stage.equals("closed")) { rotate(initial.getRefreshToken().getTokenValue(), Set.of("profile")); }
			if (stage.equals("quarantined")) { rejection(request(code, authenticatedClient(code)), "invalid_grant"); }
		}
		var before = stored(code); var binding = this.bindings.findByAuthorization(before.authorization()).orElseThrow();
		var history = this.jdbc.sql("SELECT * FROM iam_refresh_history ORDER BY digest").query().listOfRows();
		assertThat(revoke(binding.id())).isTrue(); var after = stored(code);
		assertThat(after.version()).isEqualTo(before.version() + 1);
		assertThat(IdentityAuthorizations.isRevoked(after.authorization())).isTrue();
		assertThat(after.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		if (after.authorization().getAccessToken() != null) {
			assertThat(after.authorization().getAccessToken().isInvalidated()).isTrue();
			assertThat(after.authorization().getToken(OidcIdToken.class).isInvalidated()).isTrue();
			assertThat(this.online.use(after.authorization().getAccessToken().getToken().getTokenValue(), this.signing.id(), context -> context.token())).isEmpty();
		}
		if (after.authorization().getRefreshToken() != null) { assertThat(after.authorization().getRefreshToken().isInvalidated()).isTrue(); }
		assertThat(this.bindings.findByAuthorization(after.authorization())).contains(binding);
		assertThat(this.jdbc.sql("SELECT * FROM iam_refresh_history ORDER BY digest").query().listOfRows()).isEqualTo(history);
		if (!history.isEmpty()) { assertThat(this.refresh.findByAuthorization(after.authorization())).get().satisfies(family -> assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.REVOKED)); }
		var audit = revocationAudits();
		assertThat(audit).singleElement().satisfies(row -> assertThat(row).containsEntry("target_user_id", this.userId).containsEntry("target_id", binding.id())
				.containsEntry("target_type", "authorization").containsEntry("outcome", "success").containsEntry("actor", AUDIT.actor())
				.containsEntry("source", AUDIT.source()).containsEntry("correlation_id", AUDIT.correlationId()));
		assertThat(this.jdbc.sql("SELECT row_to_json(a)::text FROM iam_security_audit a WHERE action='authorization_revoked'").query(String.class).single()).doesNotContain(code, this.secret, PASSWORD, "alice");
		assertThat(revoke(binding.id())).isFalse(); assertThat(stored(code)).isEqualTo(after); assertThat(revocationAudits()).isEqualTo(audit);
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void revokedCodesAreDeniedWithoutBeingMisclassifiedAsConsumedCodeReplay(boolean exchanged) {
		String code = code(Set.of("openid", "offline_access")); var request = request(code, authenticatedClient(code));
		if (exchanged) { exchange(request); }
		revoke(UUID.fromString(stored(code).authorization().getId())); var after = stored(code);
		rejection(request, "invalid_grant"); assertThat(stored(code)).isEqualTo(after);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='authorization_code_replayed'").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='token_request_rejected'").query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void revocationRejectsBothCurrentAndSpentRefreshTokensWithoutCreatingAnotherReplayQuarantine() {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		String parent = initial.getRefreshToken().getTokenValue(); var next = rotate(parent, Set.of());
		revoke(UUID.fromString(stored(code).authorization().getId())); var after = stored(code);
		for (String value : List.of(parent, next.getRefreshToken().getTokenValue())) {
			var ex = catchThrowableOfType(OAuth2AuthenticationException.class, () -> rotate(value, Set.of()));
			assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"); assertThat(stored(code)).isEqualTo(after);
		}
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='refresh_token_replayed'").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@ValueSource(strings = { "remove", "false", "code", "access", "refresh", "id" })
	void protectedRevocationCannotBeRemovedOrUsedToReactivateAnyNativeToken(String change) {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code)));
		revoke(UUID.fromString(stored(code).authorization().getId())); var after = stored(code); var candidate = OAuth2Authorization.from(after.authorization());
		switch (change) {
			case "remove" -> candidate.attributes(attributes -> attributes.remove("iam.authorizationRevoked"));
			case "false" -> candidate.attribute("iam.authorizationRevoked", false);
			default -> {
				var token = switch (change) {
					case "code" -> after.authorization().getToken(OAuth2AuthorizationCode.class);
					case "access" -> after.authorization().getAccessToken(); case "refresh" -> after.authorization().getRefreshToken();
					default -> after.authorization().getToken(OidcIdToken.class);
				};
				candidate.token(token.getToken(), metadata -> { metadata.putAll(token.getMetadata()); metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false); });
			}
		}
		assertThatIllegalStateException().isThrownBy(() -> this.authorizations.save(candidate.build(), after.version()));
		assertThat(stored(code)).isEqualTo(after);
	}

	@ParameterizedTest
	@ValueSource(strings = { "user", "client", "resource", "role", "user-resource" })
	void bulkRevocationSelectsOnlyItsImmutableOwnershipBoundary(String selection) {
		UUID otherUser = activeUser("bob"); String otherSession = browserSession(otherUser, this.authenticatedAt);
		UUID otherResource = this.resources.create("urn:example:billing", "Billing", AUDIT).id();
		UUID sibling = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT).client().id();
		UUID foreign = this.clients.create(configuration(otherResource, Set.of()), AUDIT).client().id();
		var grants = List.of(code(Set.of("openid")), codeFor(this.userId, this.sessionId, sibling), codeFor(otherUser, otherSession, this.clientId),
				codeFor(this.userId, this.sessionId, foreign), codeFor(otherUser, otherSession, foreign));
		Set<Integer> expected = switch (selection) {
			case "user" -> Set.of(0, 1, 3); case "client" -> Set.of(0, 2); case "resource" -> Set.of(0, 1, 2); default -> Set.of(0, 1);
		};
		int changed = new TransactionTemplate(this.transactions).execute(tx -> {
			this.users.lockById(this.userId); this.resources.lockById(this.resourceId);
			return switch (selection) {
				case "user" -> this.revocations.revokeForUser(this.userId, AUDIT); case "client" -> this.revocations.revokeForClient(this.clientId, AUDIT);
				case "resource" -> this.revocations.revokeForResource(this.resourceId, AUDIT); case "role" -> this.revocations.revokeForRole(this.roleId, AUDIT);
				default -> this.revocations.revokeForUserResource(this.userId, this.resourceId, AUDIT);
			};
		});
		assertThat(changed).isEqualTo(expected.size());
		for (int i = 0; i < grants.size(); i++) { assertThat(IdentityAuthorizations.isRevoked(stored(grants.get(i)).authorization())).isEqualTo(expected.contains(i)); }
		assertThat(revocationAudits()).hasSize(expected.size());
	}

	@Test
	void roleRevocationIncludesCurrentAssigneesWhoseGrantWasIssuedWhileTheRoleWasInactive() {
		this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		String code = code(Set.of("openid"));
		assertThat(this.bindings.findByAuthorization(stored(code).authorization()).orElseThrow().session().access().roles()).isEmpty();
		assertThat(new TransactionTemplate(this.transactions).<Integer>execute(tx -> {
			this.resources.lockById(this.resourceId); return this.revocations.revokeForRole(this.roleId, AUDIT);
		})).isEqualTo(1);
		assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue();
	}

	@Test
	void originalResourceSelectionStillFindsGrantsAfterTheirClientMovesToAnotherResource() {
		String code = code(Set.of("openid")); UUID next = this.resources.create("urn:example:billing", "Billing", AUDIT).id();
		this.clients.updateConfiguration(this.clientId, 1, configuration(next, Set.of()), AUDIT);
		assertThat(new TransactionTemplate(this.transactions).<Integer>execute(tx -> {
			this.resources.lockById(this.resourceId); return this.revocations.revokeForResource(this.resourceId, AUDIT);
		})).isEqualTo(1);
		assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue();
	}

	@Test
	void bulkRevocationDoesNotStopAtTheManagementSearchPageLimit() {
		for (int i = 0; i < 105; i++) { code(Set.of("openid")); }
		assertThat(new TransactionTemplate(this.transactions).<Integer>execute(tx -> {
			this.users.lockById(this.userId); return this.revocations.revokeForUser(this.userId, AUDIT);
		})).isEqualTo(105);
		assertThat(revocationAudits()).hasSize(105);
		for (String value : this.jdbc.sql("SELECT authorization_id FROM iam_authorization_binding").query(String.class).list()) {
			assertThat(IdentityAuthorizations.isRevoked(this.authorizations.findById(UUID.fromString(value)).orElseThrow().authorization())).isTrue();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "native-skip", "family-skip", "audit-skip", "audit-change", "audit-commit", "family-commit" })
	void writeSuppressionAuditMutationAndDeferredCommitFailuresRollbackTheCompleteRevocationAndAllowRetry(String failure) {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code))); var before = stored(code);
		var family = this.refresh.findByAuthorization(before.authorization()); var history = this.jdbc.sql("SELECT * FROM iam_refresh_history").query().listOfRows();
		switch (failure) {
			case "native-skip" -> fault("oauth2_authorization", "BEFORE UPDATE", "RETURN NULL;", false);
			case "family-skip" -> fault("iam_refresh_family", "BEFORE UPDATE", "RETURN NULL;", false);
			case "audit-skip" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_revoked' THEN RETURN NULL; END IF; RETURN NEW;", false);
			case "audit-change" -> fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_revoked' THEN NEW.actor='system:changed'; END IF; RETURN NEW;", false);
			case "audit-commit" -> fault("iam_security_audit", "AFTER INSERT", "IF NEW.action='authorization_revoked' THEN RAISE EXCEPTION 'isolated revocation commit'; END IF; RETURN NEW;", true);
			default -> fault("iam_refresh_family", "AFTER UPDATE", "IF NEW.status='revoked' THEN RAISE EXCEPTION 'isolated family commit'; END IF; RETURN NEW;", true);
		}
		assertThatThrownBy(() -> revoke(UUID.fromString(before.authorization().getId()))).isInstanceOf(RuntimeException.class);
		assertThat(stored(code)).isEqualTo(before); assertThat(this.refresh.findByAuthorization(before.authorization())).isEqualTo(family);
		assertThat(this.jdbc.sql("SELECT * FROM iam_refresh_history").query().listOfRows()).isEqualTo(history); assertThat(revocationAudits()).isEmpty();
		String table = failure.startsWith("native") ? "oauth2_authorization" : failure.startsWith("family") ? "iam_refresh_family" : "iam_security_audit";
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON " + table).update(); this.jdbc.sql("DROP FUNCTION exchange_test_fault()").update();
		assertThat(revoke(UUID.fromString(before.authorization().getId()))).isTrue();
	}

	@Test
	void aFailureAfterTheFirstBulkRevocationRollsBackEveryEarlierGrantAndAudit() {
		var codes = List.of(code(Set.of("openid", "offline_access")), code(Set.of("openid")), code(Set.of("openid", "offline_access")));
		for (String code : codes) { exchange(request(code, authenticatedClient(code))); }
		var before = codes.stream().map(this::stored).toList();
		var families = before.stream().map(value -> this.refresh.findByAuthorization(value.authorization())).toList();
		this.jdbc.sql("CREATE SEQUENCE exchange_test_audit_probe").update();
		fault("iam_security_audit", "BEFORE INSERT", "IF NEW.action='authorization_revoked' AND nextval('exchange_test_audit_probe')=2 THEN RAISE EXCEPTION 'isolated bulk revocation'; END IF; RETURN NEW;", false);
		assertThatThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> {
			this.users.lockById(this.userId); return this.revocations.revokeForUser(this.userId, AUDIT);
		})).isInstanceOf(RuntimeException.class);
		assertThat(codes.stream().map(this::stored).toList()).isEqualTo(before);
		assertThat(before.stream().map(value -> this.refresh.findByAuthorization(value.authorization())).toList()).isEqualTo(families);
		assertThat(revocationAudits()).isEmpty();
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON iam_security_audit").update(); this.jdbc.sql("DROP FUNCTION exchange_test_fault()").update();
		assertThat(new TransactionTemplate(this.transactions).<Integer>execute(tx -> {
			this.users.lockById(this.userId); return this.revocations.revokeForUser(this.userId, AUDIT);
		})).isEqualTo(3);
	}

	@ParameterizedTest
	@ValueSource(strings = { "no-user", "no-type", "no-object", "wrong-type", "failure-outcome" })
	void theDatabaseRequiresASuccessfulRevocationToIdentifyBothItsUserAndAuthorization(String invalid) {
		assertThatThrownBy(() -> this.jdbc.sql("""
				INSERT INTO iam_security_audit(id,actor,source,correlation_id,target_user_id,action,outcome,target_type,target_id)
				VALUES (:id,:actor,:source,:correlation,:user,'authorization_revoked',:outcome,:type,:object)
				""").param("id", UUID.randomUUID()).param("actor", AUDIT.actor()).param("source", AUDIT.source()).param("correlation", AUDIT.correlationId())
				.param("user", invalid.equals("no-user") ? null : this.userId, Types.OTHER)
				.param("type", invalid.equals("no-type") ? null : invalid.equals("wrong-type") ? "client" : "authorization", Types.VARCHAR)
				.param("object", invalid.equals("no-object") ? null : UUID.randomUUID(), Types.OTHER)
				.param("outcome", invalid.equals("failure-outcome") ? "failure" : "success").update()).isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	void aRefreshWaitingForTheSubjectSeesTheCommittedRevocationBeforeGeneratingAnotherToken() throws Exception {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		var request = new OAuth2RefreshTokenAuthenticationToken(initial.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), Map.of());
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					this.users.lockById(this.userId); locked.countDown(); awaitLatch(release); return this.revocations.revokeForUser(this.userId, AUDIT);
				}));
				awaitLatch(locked); var reader = executor.submit(() -> {
					serverContext("https://iam.example");
					try { return catchThrowableOfType(OAuth2AuthenticationException.class, () -> refreshProvider().authenticate(request)).getError().getErrorCode(); }
					finally { AuthorizationServerContextHolder.resetContext(); }
				});
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR SHARE%')").query(Boolean.class).single());
				release.countDown(); assertThat(writer.get(10, TimeUnit.SECONDS)).isEqualTo(1); assertThat(reader.get(10, TimeUnit.SECONDS)).isEqualTo("invalid_grant");
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_refresh_history").query(Long.class).single()).isEqualTo(1);
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void validationFinishesBeforeTheWaitingRevocationAndTheFollowingUseIsRejected() throws Exception {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getAccessToken().getTokenValue();
		var validating = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var reader = executor.submit(() -> this.online.use(token, this.signing.id(), context -> { validating.countDown(); awaitLatch(release); return context.token(); }));
				awaitLatch(validating); var writer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					this.users.lockById(this.userId); return this.revocations.revokeForUser(this.userId, AUDIT);
				}));
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR UPDATE%')").query(Boolean.class).single());
				release.countDown(); assertThat(reader.get(10, TimeUnit.SECONDS)).isPresent(); assertThat(writer.get(10, TimeUnit.SECONDS)).isEqualTo(1);
				assertThat(this.online.use(token, this.signing.id(), context -> context.token())).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void missingGrantsAreIdempotentAndEveryInvocationRequiresTheCallersWritableReadCommittedTransaction() {
		UUID unknown = UUID.randomUUID(); assertThat(revoke(unknown)).isFalse(); assertThat(revocationAudits()).isEmpty();
		assertThatThrownBy(() -> this.revocations.revokeForUser(unknown, AUDIT)).isInstanceOf(IllegalTransactionStateException.class);
		var readOnly = new TransactionTemplate(this.transactions); readOnly.setReadOnly(true);
		assertThatIllegalStateException().isThrownBy(() -> readOnly.execute(tx -> this.revocations.revokeForUser(unknown, AUDIT)));
		var repeatable = new TransactionTemplate(this.transactions); repeatable.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		assertThatIllegalStateException().isThrownBy(() -> repeatable.execute(tx -> this.revocations.revokeForUser(unknown, AUDIT)));
		assertThat(new TransactionTemplate(this.transactions).<Integer>execute(tx -> this.revocations.revokeForUser(unknown, AUDIT))).isZero();
	}

	private boolean revoke(UUID id) {
		return new TransactionTemplate(this.transactions).execute(tx -> { this.users.lockById(this.userId); return this.revocations.revoke(id, AUDIT); });
	}
	private List<Map<String, Object>> revocationAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='authorization_revoked' ORDER BY recorded_at,id").query().listOfRows(); }
	private IdentityRefreshTokenProvider refreshProvider() { return new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions); }
	private OAuth2AccessTokenAuthenticationToken rotate(String token, Set<String> scopes) {
		return (OAuth2AccessTokenAuthenticationToken) refreshProvider().authenticate(new OAuth2RefreshTokenAuthenticationToken(token, refreshClient(this.clientId, this.secret), scopes, Map.of()));
	}
	private String codeFor(UUID userId, String sessionId, UUID clientId) {
		var browser = UsernamePasswordAuthenticationToken.authenticated(userId, null, List.of());
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", clientId.toString(), browser,
				REDIRECT, "opaque-client-state", Set.of("openid"), Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE));
		request.setDetails(new IdentityAuthorizationRequestProvider.BrowserEvidence(sessionId, this.authenticatedAt, 1, UUID.randomUUID()));
		return ((OAuth2AuthorizationCodeRequestAuthenticationToken) this.requests.authenticate(request)).getAuthorizationCode().getTokenValue();
	}

}
