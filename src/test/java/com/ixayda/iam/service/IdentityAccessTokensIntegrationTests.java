package com.ixayda.iam.service;

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
import java.util.concurrent.atomic.AtomicBoolean;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityAccessToken;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityAccessTokensIntegrationTests extends IdentityProtocolTestSupport {

	@Autowired private IdentityAccessTokens online;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityResourceCredentials credentials;

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void issuedAccessIsBoundToItsCurrentIdentityResourceScopesAndPublicKeyWithoutMutatingTheGrant(boolean offline) {
		String code = code(offline ? Set.of("openid", "profile", "offline_access") : Set.of("openid", "profile"));
		var initial = exchange(request(code, authenticatedClient(code))); var before = stored(code);
		var found = this.online.useForResource(initial.getAccessToken().getTokenValue(), this.signing.id(), this.resourceId,
				context -> verifiedAccess(context, initial.getAccessToken().getTokenValue()));
		assertThat(found).get().satisfies(token -> {
			assertThat(token.authorizationId().toString()).isEqualTo(before.authorization().getId());
			assertThat(token.access().userId()).isEqualTo(this.userId); assertThat(token.access().clientId()).isEqualTo(this.clientId);
			assertThat(token.access().resourceId()).isEqualTo(this.resourceId); assertThat(token.access().audience()).isEqualTo("urn:example:orders");
			assertThat(token.access().roles()).extracting(role -> role.code()).containsExactly("reader");
			assertThat(token.scopes()).isEqualTo(initial.getAccessToken().getScopes());
			assertThat(token.toString()).doesNotContain(initial.getAccessToken().getTokenValue(), this.userId.toString(), this.secret);
		});
		assertThat(stored(code)).isEqualTo(before); assertThat(tokenAudits()).hasSize(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "unknown", "code", "id", "refresh" })
	void aMissingTokenOrAnotherCredentialPurposeCannotReachTheTrustedVerifier(String purpose) {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		String value = switch (purpose) {
			case "code" -> code; case "id" -> (String) initial.getAdditionalParameters().get("id_token");
			case "refresh" -> initial.getRefreshToken().getTokenValue(); default -> "unknown-token";
		};
		var invoked = new AtomicBoolean();
		assertThat(this.online.use(value, this.signing.id(), context -> { invoked.set(true); return context; })).isEmpty(); assertThat(invoked).isFalse();
	}

	@Test
	void theAuthenticatedResourceAndStoredSigningKeyCannotBeSubstitutedFromTheRequest() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); var invoked = new AtomicBoolean();
		assertThat(this.online.useForResource(initial.getAccessToken().getTokenValue(), this.signing.id(), UUID.randomUUID(), context -> { invoked.set(true); return context; })).isEmpty();
		assertThat(this.online.use(initial.getAccessToken().getTokenValue(), UUID.randomUUID(), context -> { invoked.set(true); return context; })).isEmpty();
		assertThat(invoked).isFalse(); assertThat(accepted(initial.getAccessToken().getTokenValue())).isPresent();
	}

	@Test
	void applicationAccessDoesNotDependOnTheOriginalBrowserSession() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); this.store.deleteById(this.sessionId);
		assertThat(accepted(initial.getAccessToken().getTokenValue())).isPresent();
	}

	@ParameterizedTest
	@ValueSource(strings = { "user-disabled", "credential", "client-secret", "client-disabled", "client-transferred", "resource", "resource-disabled", "role", "role-disabled", "assignment" })
	void oldAccessIsRejectedAfterAnyBoundSecurityVersionOrAvailabilityChanges(String mutation) {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code))); mutate(mutation); var afterMutation = stored(code);
		assertThat(accepted(initial.getAccessToken().getTokenValue())).isEmpty();
		assertThat(stored(code)).isEqualTo(afterMutation);
	}

	@Test
	void disableAndReenableCannotReviveTheOldClientGrant() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code)));
		this.clients.setEnabled(this.clientId, 1, false, AUDIT); this.clients.setEnabled(this.clientId, 2, true, AUDIT);
		assertThat(accepted(initial.getAccessToken().getTokenValue())).isEmpty();
	}

	@Test
	void disablingAndReenablingTheSubjectDoesNotRestoreItsOldApplicationAccess() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code)));
		this.states.disable(this.userId, AUDIT); this.states.enable(this.userId, AUDIT);
		assertThat(accepted(initial.getAccessToken().getTokenValue())).isEmpty();
	}

	@ParameterizedTest
	@ValueSource(strings = { "openid,offline_access", "profile,offline_access", "profile", "openid" })
	void onlineProjectionUsesCurrentScopesAfterRefreshEvenWhenTheNativeOriginalScopesRemainUnchanged(String desired) {
		String code = code(Set.of("openid", "profile", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		var next = rotate(initial.getRefreshToken().getTokenValue(), Set.of(desired.split(",")));
		assertThat(accepted(initial.getAccessToken().getTokenValue())).isEmpty();
		assertThat(accepted(next.getAccessToken().getTokenValue())).get().satisfies(token -> assertThat(token.scopes()).containsExactlyInAnyOrder(desired.split(",")));
		assertThat(stored(code).authorization().getAuthorizedScopes()).containsExactlyInAnyOrder("openid", "profile", "offline_access");
	}

	@Test
	void codeReplayPreventsFurtherOnlineAccessToBothOfflineAndOrdinaryGrants() {
		for (boolean offline : List.of(false, true)) {
			String code = code(offline ? Set.of("openid", "offline_access") : Set.of("openid")); var request = request(code, authenticatedClient(code)); var initial = exchange(request);
			rejection(request, "invalid_grant"); assertThat(accepted(initial.getAccessToken().getTokenValue())).isEmpty();
		}
	}

	@Test
	void aReplayQuarantineAlsoBlocksTheLastRotatedAccessToken() {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		String parent = initial.getRefreshToken().getTokenValue(); var next = rotate(parent, Set.of());
		assertThatThrownBy(() -> rotate(parent, Set.of())).isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class);
		assertThat(accepted(next.getAccessToken().getTokenValue())).isEmpty();
	}

	@Test
	void privateSigningCorruptionCannotDisableValidationThroughThePersistedPublicKey() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code)));
		byte[] encrypted = this.jdbc.sql("SELECT encrypted_private_key FROM iam_signing_key").query(byte[].class).single();
		try {
			this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)").update();
			assertThatIllegalStateException().isThrownBy(this.keys::signingMaterial);
			assertThat(accepted(initial.getAccessToken().getTokenValue())).isPresent();
		}
		finally { this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=:value").param("value", encrypted).update(); }
	}

	@Test
	void validationHoldsThePublicKeyLifecycleUntilTheAcceptedResultCommits() throws Exception {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getAccessToken().getTokenValue();
		var validating = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var reader = executor.submit(() -> this.online.use(token, this.signing.id(), context -> { validating.countDown(); awaitLatch(release); return verifiedAccess(context, token); }));
				awaitLatch(validating);
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx ->
						this.jdbc.sql("SELECT singleton FROM iam_signing_key_state WHERE singleton=1 FOR UPDATE").query(Integer.class).single()));
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%iam_signing_key_state%FOR UPDATE%')").query(Boolean.class).single());
				assertThat(writer.isDone()).isFalse(); release.countDown(); assertThat(reader.get(10, TimeUnit.SECONDS)).isPresent(); writer.get(10, TimeUnit.SECONDS);
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void differentSubjectsCanValidateTheSameResourceConcurrentlyWithoutUpgradingItsSharedLock() throws Exception {
		var issued = this.credentials.rotateSecret(this.resourceId, 0, AUDIT);
		var credential = this.credentials.authenticate(this.resourceId.toString(), issued.secret()).orElseThrow();
		UUID firstUser = this.userId;
		String firstCode = code(Set.of("openid"));
		String firstToken = exchange(request(firstCode, authenticatedClient(firstCode))).getAccessToken().getTokenValue();
		this.userId = activeUser("bob");
		this.assignments.change(this.userId, this.roleId, 0, true, AUDIT);
		this.sessionId = browserSession(this.userId, this.authenticatedAt);
		UUID secondUser = this.userId;
		String secondCode = code(Set.of("openid"));
		String secondToken = exchange(request(secondCode, authenticatedClient(secondCode))).getAccessToken().getTokenValue();
		assertThat(secondUser).isNotEqualTo(firstUser);
		long deadlocks = this.jdbc.sql("SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()").query(Long.class).single();
		var projected = new CountDownLatch(2);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> this.online.useForResource(firstToken, this.signing.id(), this.resourceId, context -> {
				projected.countDown(); awaitLatch(projected);
				assertThat(this.credentials.lockForValidation(credential)).contains(credential);
				return verifiedAccess(context, firstToken).access().userId();
			}));
			var second = executor.submit(() -> this.online.useForResource(secondToken, this.signing.id(), this.resourceId, context -> {
				projected.countDown(); awaitLatch(projected);
				assertThat(this.credentials.lockForValidation(credential)).contains(credential);
				return verifiedAccess(context, secondToken).access().userId();
			}));
			assertThat(first.get(15, TimeUnit.SECONDS)).contains(firstUser);
			assertThat(second.get(15, TimeUnit.SECONDS)).contains(secondUser);
		}
		assertThat(this.jdbc.sql("SELECT deadlocks FROM pg_stat_database WHERE datname=current_database()").query(Long.class).single()).isEqualTo(deadlocks);
	}

	@Test
	void aCredentialChangeCommittedWhileWaitingForTheSubjectLockIsReadAgainBeforeAcceptance() throws Exception {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					this.jdbc.sql("SELECT id FROM iam_user WHERE id=:id FOR UPDATE").param("id", this.userId).query(UUID.class).single();
					locked.countDown(); awaitLatch(release); mutate("credential");
				}));
				awaitLatch(locked); var reader = executor.submit(() -> accepted(initial.getAccessToken().getTokenValue()));
				await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FROM iam_user WHERE id%FOR SHARE%')").query(Boolean.class).single());
				release.countDown(); writer.get(10, TimeUnit.SECONDS); assertThat(reader.get(10, TimeUnit.SECONDS)).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void accessExpiryDuringTrustedVerificationCannotPublishThePreviouslyActiveResult() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); var before = stored(code); var token = initial.getAccessToken();
		Instant expiry = Instant.now().plusSeconds(2).truncatedTo(ChronoUnit.MICROS);
		this.authorizations.save(OAuth2Authorization.from(before.authorization()).token(new OAuth2AccessToken(token.getTokenType(), token.getTokenValue(), token.getIssuedAt(), expiry, token.getScopes()),
				metadata -> metadata.putAll(before.authorization().getAccessToken().getMetadata())).build(), before.version());
		var invoked = new AtomicBoolean();
		assertThat(this.online.use(token.getTokenValue(), this.signing.id(), context -> {
			invoked.set(true); var verified = verifiedAccess(context, token.getTokenValue());
			await().atMost(Duration.ofSeconds(5)).until(() -> Instant.now().isAfter(expiry)); return verified;
		})).isEmpty();
		assertThat(invoked).isTrue();
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void aFutureOrExpiredStoredAccessLifetimeCannotReachTrustedVerification(boolean future) {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); var before = stored(code); var token = initial.getAccessToken();
		Instant issued = future ? Instant.now().plusSeconds(30).truncatedTo(ChronoUnit.MICROS) : token.getIssuedAt();
		Instant expiry = future ? issued.plusSeconds(30) : issued.plusMillis(1);
		this.authorizations.save(OAuth2Authorization.from(before.authorization()).token(new OAuth2AccessToken(token.getTokenType(), token.getTokenValue(), issued, expiry, token.getScopes()),
				metadata -> metadata.putAll(before.authorization().getAccessToken().getMetadata())).build(), before.version());
		if (!future) { await().atMost(Duration.ofSeconds(2)).until(() -> Instant.now().isAfter(expiry)); }
		var invoked = new AtomicBoolean();
		assertThat(this.online.use(token.getTokenValue(), this.signing.id(), context -> { invoked.set(true); return context; })).isEmpty();
		assertThat(invoked).isFalse();
	}

	@Test
	void mandatoryCurrentFamilyIntegrityCannotBeReplacedByAnActiveNativeAccessToken() {
		String code = code(Set.of("openid", "offline_access")); var initial = exchange(request(code, authenticatedClient(code)));
		this.jdbc.sql("UPDATE iam_refresh_family SET version=version+1,status='quarantined'").update();
		assertThatIllegalStateException().isThrownBy(() -> accepted(initial.getAccessToken().getTokenValue()));
	}

	@Test
	void trustedVerificationMustReturnAResultAndAmbientTransactionsCannotReceiveUncommittedProof() {
		String code = code(Set.of("openid")); var initial = exchange(request(code, authenticatedClient(code))); String token = initial.getAccessToken().getTokenValue();
		assertThatIllegalStateException().isThrownBy(() -> this.online.use(token, this.signing.id(), context -> null));
		assertThatIllegalStateException().isThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> accepted(token)));
		assertThat(accepted(token)).isPresent();
	}

	private java.util.Optional<IdentityAccessToken> accepted(String value) { return this.online.use(value, this.signing.id(), context -> verifiedAccess(context, value)); }
	private IdentityAccessToken verifiedAccess(IdentityAccessTokens.Context context, String value) {
		try {
			var signed = SignedJWT.parse(value); var token = context.token(); var claims = signed.getJWTClaimsSet();
			assertThat(signed.verify(new RSASSAVerifier(context.key().publicKey()))).isTrue();
			assertThat(signed.getHeader().getAlgorithm().getName()).isEqualTo("RS256"); assertThat(signed.getHeader().getType().toString()).isEqualTo("at+jwt");
			assertThat(signed.getHeader().getKeyID()).isEqualTo(context.key().id().toString());
			assertThat(claims.getIssuer()).isEqualTo("https://iam.example"); assertThat(claims.getAudience()).containsExactly(token.access().audience());
			assertThat(claims.getSubject()).isEqualTo(token.access().userId().toString()); assertThat(claims.getStringClaim("client_id")).isEqualTo(token.access().clientId().toString());
			assertThat(claims.getStringClaim("authorization_id")).isEqualTo(token.authorizationId().toString());
			assertThat(claims.getStringClaim("scope")).isEqualTo(String.join(" ", token.scopes().stream().sorted().toList()));
			assertThat(claims.getStringListClaim("roles")).containsExactlyElementsOf(token.access().roles().stream().map(role -> role.code()).sorted().toList());
			assertThat(claims.getExpirationTime().toInstant()).isAfterOrEqualTo(token.expiresAt().truncatedTo(ChronoUnit.MILLIS));
			return token;
		}
		catch (Exception ex) { throw new AssertionError("Issued access token could not be verified", ex); }
	}
	private OAuth2AccessTokenAuthenticationToken rotate(String token, Set<String> scopes) {
		return (OAuth2AccessTokenAuthenticationToken) new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions)
				.authenticate(new OAuth2RefreshTokenAuthenticationToken(token, refreshClient(this.clientId, this.secret), scopes, Map.of()));
	}

}
