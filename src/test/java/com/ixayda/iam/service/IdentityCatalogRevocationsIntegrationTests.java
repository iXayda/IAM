package com.ixayda.iam.service;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.security.IdentityAuthorizationRequestProvider;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityCatalogRevocationsIntegrationTests extends IdentityProtocolTestSupport {

	private static final List<String> SNAPSHOT_TABLES = List.of("iam_resource", "iam_resource_role", "iam_user_role", "iam_user_resource_role_revision",
			"oauth2_registered_client", "iam_client", "iam_client_allowed_role", "oauth2_authorization", "iam_authorization_record",
			"iam_authorization_token_index", "iam_authorization_binding", "iam_refresh_family", "iam_refresh_history", "iam_security_audit");
	@Autowired private IdentityAccessTokens online;

	@ParameterizedTest
	@EnumSource(Mutation.class)
	void catalogChangesRevokeEveryAffectedGrantWithinTheOriginalOwnershipBoundary(Mutation mutation) {
		var prepared = prepare(mutation); var before = prepared.codes().stream().map(this::stored).toList();
		prepared.change().run();
		for (int i = 0; i < prepared.codes().size(); i++) {
			var after = stored(prepared.codes().get(i)); boolean affected = prepared.affected().contains(i);
			assertThat(IdentityAuthorizations.isRevoked(after.authorization())).isEqualTo(affected);
			if (!affected) { assertThat(after).isEqualTo(before.get(i)); }
			if (after.authorization().getAccessToken() != null) {
				assertThat(this.online.use(after.authorization().getAccessToken().getToken().getTokenValue(), this.signing.id(), context -> context.token()).isPresent()).isEqualTo(!affected);
			}
		}
		assertThat(revocationAudits()).hasSize(prepared.affected().size()).allSatisfy(row -> assertThat(row).containsEntry("actor", AUDIT.actor())
				.containsEntry("source", AUDIT.source()).containsEntry("correlation_id", AUDIT.correlationId()).containsEntry("target_type", "authorization"));
	}

	@ParameterizedTest
	@MethodSource("rollbackCases")
	void revocationFailureRollsBackTheCatalogEpochNativeTokensFamiliesAndAudit(Mutation mutation, boolean deferred) {
		var prepared = prepare(mutation); var before = snapshot();
		fault("iam_security_audit", deferred ? "AFTER INSERT" : "BEFORE INSERT",
				"IF NEW.action='authorization_revoked' THEN " + (deferred ? "RAISE EXCEPTION 'isolated catalog revocation';" : "RETURN NULL;") + " END IF; RETURN NEW;", deferred);
		assertThatThrownBy(prepared.change()::run).isInstanceOf(RuntimeException.class); assertThat(snapshot()).isEqualTo(before);
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON iam_security_audit").update(); this.jdbc.sql("DROP FUNCTION exchange_test_fault()").update();
		prepared.change().run();
		for (int i : prepared.affected()) { assertThat(IdentityAuthorizations.isRevoked(stored(prepared.codes().get(i)).authorization())).isTrue(); }
	}

	@Test
	void equalNormalizedUpdatesDoNotRevokeOrRecordAdditionalEvents() {
		String code = code(Set.of("openid", "offline_access")); exchange(request(code, authenticatedClient(code))); var before = snapshot();
		this.resources.updateDisplayName(this.resourceId, 1, "Orders", AUDIT); this.resources.setEnabled(this.resourceId, 1, true, AUDIT);
		this.roles.updateDisplayName(this.roleId, 1, "Reader", AUDIT); this.roles.setEnabled(this.roleId, 1, true, AUDIT);
		this.clients.updateConfiguration(this.clientId, 1, configuration(this.resourceId, Set.of(this.roleId)), AUDIT); this.clients.setEnabled(this.clientId, 1, true, AUDIT);
		assertThat(this.assignments.change(this.userId, this.roleId, 1, true, AUDIT).changed()).isFalse(); assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void staleMutationsPreserveTheGrantAndDoNotCreateRevocationEvents() {
		String code = code(Set.of("openid")); var before = snapshot();
		assertThatThrownBy(() -> this.resources.setEnabled(this.resourceId, 99, false, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThatThrownBy(() -> this.roles.setEnabled(this.roleId, 99, false, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThatThrownBy(() -> this.clients.rotateSecret(this.clientId, 99, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThatThrownBy(() -> this.assignments.change(this.userId, this.roleId, 99, false, AUDIT)).isInstanceOf(OptimisticLockingFailureException.class);
		assertThat(snapshot()).isEqualTo(before); assertUnconsumed(code);
	}

	@Test
	void reenablingARoleRevokesAssigneesGrantsWhichNeverContainedThatRole() {
		this.roles.setEnabled(this.roleId, 1, false, AUDIT); String code = code(Set.of("openid", "offline_access"));
		exchange(request(code, authenticatedClient(code)));
		assertThat(this.bindings.findByAuthorization(stored(code).authorization()).orElseThrow().session().access().roles()).isEmpty();
		this.roles.setEnabled(this.roleId, 2, true, AUDIT);
		assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue(); assertThat(revocationAudits()).hasSize(1);
	}

	@Test
	void clientTransferRevokesOldGrantsWithoutMovingTheirOriginalResourceOrRevokingLaterDestinationGrants() {
		String oldCode = code(Set.of("openid")); UUID destination = this.resources.create("urn:example:billing", "Billing", AUDIT).id();
		this.clients.updateConfiguration(this.clientId, 1, configuration(destination, Set.of()), AUDIT);
		assertThat(IdentityAuthorizations.isRevoked(stored(oldCode).authorization())).isTrue();
		assertThat(this.bindings.findByAuthorization(stored(oldCode).authorization()).orElseThrow().session().access().resourceId()).isEqualTo(this.resourceId);
		String nextCode = code(Set.of("openid", "offline_access")); var tokens = exchange(request(nextCode, authenticatedClient(nextCode)));
		this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		assertThat(IdentityAuthorizations.isRevoked(stored(nextCode).authorization())).isFalse(); assertThat(revocationAudits()).hasSize(1);
		assertThat(this.online.use(tokens.getAccessToken().getTokenValue(), this.signing.id(), context -> context.token())).isPresent();
	}

	@Test
	void resourceMutationDoesNotAcquireAffectedUsersAfterTheCatalogLockOrDeadlockAWaitingRefresh() throws Exception {
		String code = code(Set.of("openid", "offline_access")); var tokens = exchange(request(code, authenticatedClient(code)));
		var request = new OAuth2RefreshTokenAuthenticationToken(tokens.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), Map.of());
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					this.resources.lockById(this.resourceId); locked.countDown(); awaitLatch(release);
					return this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
				}));
				awaitLatch(locked); var reader = executor.submit(() -> {
					serverContext("https://iam.example");
					try { return catchThrowableOfType(OAuth2AuthenticationException.class, () -> provider.authenticate(request)); }
					finally { AuthorizationServerContextHolder.resetContext(); }
				});
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%iam_resource%FOR%')").query(Boolean.class).single());
				release.countDown(); assertThat(writer.get(10, TimeUnit.SECONDS)).isNotNull();
				assertThat(reader.get(10, TimeUnit.SECONDS)).isNotNull().satisfies(ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"));
				assertThat(IdentityAuthorizations.isRevoked(stored(code).authorization())).isTrue();
			}
			finally { release.countDown(); }
		}
	}

	private Prepared prepare(Mutation mutation) {
		UUID otherUser = activeUser("bobby"); this.assignments.change(otherUser, this.roleId, 0, true, AUDIT);
		String otherSession = browserSession(otherUser, this.authenticatedAt);
		var sibling = this.clients.create(configuration(this.resourceId, Set.of(this.roleId)), AUDIT);
		UUID foreignResource = this.resources.create("urn:example:billing", "Billing", AUDIT).id();
		var foreign = this.clients.create(configuration(foreignResource, Set.of()), AUDIT);
		UUID addedRole = mutation == Mutation.ASSIGN_GRANT ? this.roles.create(this.resourceId, "writer", "Writer", AUDIT).id() : this.roleId;
		var codes = List.of(code(Set.of("openid", "offline_access")), code(Set.of("openid")), codeFor(this.userId, this.sessionId, sibling.client().id()),
				codeFor(otherUser, otherSession, this.clientId), codeFor(this.userId, this.sessionId, foreign.client().id()), codeFor(otherUser, otherSession, foreign.client().id()));
		var credentials = Map.of(this.clientId, this.secret, sibling.client().id(), sibling.secret(), foreign.client().id(), foreign.secret());
		for (int index : List.of(0, 2, 3, 4, 5)) {
			String code = codes.get(index); UUID client = UUID.fromString(stored(code).authorization().getRegisteredClientId());
			exchange(request(code, authenticatedClient(client, credentials.get(client), code)));
		}
		Runnable change = switch (mutation) {
			case CLIENT_SECRET -> () -> this.clients.rotateSecret(this.clientId, 1, AUDIT);
			case CLIENT_CONFIG -> () -> this.clients.updateConfiguration(this.clientId, 1,
					new IdentityClientConfiguration("Renamed orders", this.resourceId, List.of(REDIRECT), Set.of("openid", "profile", "offline_access"), Set.of(this.roleId)), AUDIT);
			case CLIENT_DISABLE -> () -> this.clients.setEnabled(this.clientId, 1, false, AUDIT);
			case CLIENT_ENABLE -> () -> this.clients.setEnabled(this.clientId, 2, true, AUDIT);
			case RESOURCE_RENAME -> () -> this.resources.updateDisplayName(this.resourceId, 1, "Renamed orders", AUDIT);
			case RESOURCE_DISABLE -> () -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
			case RESOURCE_ENABLE -> () -> this.resources.setEnabled(this.resourceId, 2, true, AUDIT);
			case ROLE_RENAME -> () -> this.roles.updateDisplayName(this.roleId, 1, "Renamed reader", AUDIT);
			case ROLE_DISABLE -> () -> this.roles.setEnabled(this.roleId, 1, false, AUDIT);
			case ROLE_ENABLE -> () -> this.roles.setEnabled(this.roleId, 2, true, AUDIT);
			case ASSIGN_GRANT -> () -> this.assignments.change(this.userId, addedRole, 1, true, AUDIT);
			case ASSIGN_REVOKE -> () -> this.assignments.change(this.userId, this.roleId, 1, false, AUDIT);
		};
		if (mutation == Mutation.CLIENT_ENABLE) { this.jdbc.sql("UPDATE iam_client SET status='disabled',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.clientId.toString()).update(); }
		if (mutation == Mutation.RESOURCE_ENABLE) { this.jdbc.sql("UPDATE iam_resource SET status='disabled',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.resourceId).update(); }
		if (mutation == Mutation.ROLE_ENABLE) { this.jdbc.sql("UPDATE iam_resource_role SET status='disabled',version=version+1,updated_at=clock_timestamp() WHERE id=:id").param("id", this.roleId).update(); }
		Set<Integer> affected = switch (mutation) {
			case CLIENT_SECRET, CLIENT_CONFIG, CLIENT_DISABLE, CLIENT_ENABLE -> Set.of(0, 1, 3);
			case ASSIGN_GRANT, ASSIGN_REVOKE -> Set.of(0, 1, 2); default -> Set.of(0, 1, 2, 3);
		};
		return new Prepared(change, codes, affected);
	}

	private String codeFor(UUID user, String session, UUID client) {
		var browser = UsernamePasswordAuthenticationToken.authenticated(user, null, List.of());
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", client.toString(), browser,
				REDIRECT, "opaque-client-state", Set.of("openid", "profile"), Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE));
		request.setDetails(new IdentityAuthorizationRequestProvider.BrowserEvidence(session, this.authenticatedAt, 1, UUID.randomUUID()));
		return ((OAuth2AuthorizationCodeRequestAuthenticationToken) this.requests.authenticate(request)).getAuthorizationCode().getTokenValue();
	}
	private List<List<String>> snapshot() { return SNAPSHOT_TABLES.stream().map(table -> this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList(); }
	private List<Map<String, Object>> revocationAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='authorization_revoked' ORDER BY recorded_at,id").query().listOfRows(); }
	private static Stream<Object[]> rollbackCases() { return Stream.of(Mutation.values()).flatMap(mutation -> Stream.of(new Object[] { mutation, false }, new Object[] { mutation, true })); }
	private enum Mutation { CLIENT_SECRET, CLIENT_CONFIG, CLIENT_DISABLE, CLIENT_ENABLE, RESOURCE_RENAME, RESOURCE_DISABLE, RESOURCE_ENABLE, ROLE_RENAME, ROLE_DISABLE, ROLE_ENABLE, ASSIGN_GRANT, ASSIGN_REVOKE }
	private record Prepared(Runnable change, List<String> codes, Set<Integer> affected) { }

}
