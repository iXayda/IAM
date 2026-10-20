package com.ixayda.iam.service;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.IdentityProtocolTestSupport;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.MfaRecoveryCodeContext;
import com.ixayda.iam.model.PasswordAuthenticationContext;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.IdentityAuthorizationRequestProvider;
import com.ixayda.iam.security.IdentityRefreshTokenProvider;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

class IdentityUserRevocationsIntegrationTests extends IdentityProtocolTestSupport {

	private static final Path TOTP_KEY = totpKey();
	private static final String REPLACEMENT_PASSWORD = "cobalt orchard evening passage 582";
	private static final List<String> SNAPSHOT_TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_user_totp", "iam_totp_replacement", "iam_totp_recovery",
			"iam_mfa_recovery_code", "iam_administrator", "iam_admin_bootstrap", "iam_administrator_recovery", "iam_security_audit",
			"iam_totp_authentication_limit", "iam_password_authentication_limit", "iam_mfa_recovery_limit", "oauth2_authorization",
			"iam_authorization_record", "iam_authorization_token_index", "iam_authorization_binding", "iam_refresh_family", "iam_refresh_history");
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityPasswords passwords;
	@Autowired private IdentityPasswordRecoveries passwordRecoveries;
	@Autowired private IdentityTotps totps;
	@Autowired private IdentityTotpReplacements replacements;
	@Autowired private IdentityTotpRecoveries factorRecoveries;
	@Autowired private IdentityMfaRecoveryCodes recoveryCodes;
	@Autowired private IdentityAdministrators administrators;
	@Autowired private IdentityAdministratorRecoveries administratorRecoveries;
	@Autowired private IdentityAdministratorCredentialRecoveries credentialRecoveries;
	@Autowired private IdentityAccessTokens online;

	@DynamicPropertySource
	static void factorProperties(DynamicPropertyRegistry registry) { registry.add("iam.totp.key-file", TOTP_KEY::toString); }

	@BeforeEach
	void clearBudgets() {
		this.jdbc.sql("TRUNCATE iam_password_authentication_limit,iam_totp_authentication_limit,iam_mfa_recovery_limit").update();
	}

	@ParameterizedTest
	@EnumSource(Workflow.class)
	void successfulSecurityChangesRevokeEveryOwnedGrantAndKeepOtherUsersUnaffected(Workflow workflow) {
		var prepared = prepare(workflow); var other = stored(prepared.otherCode());
		assertThat(revocationAudits()).isEmpty();
		prepared.change().run();
		for (String code : prepared.codes()) { assertTerminal(code); }
		assertThat(stored(prepared.otherCode())).isEqualTo(other);
		assertThat(this.online.use(other.authorization().getAccessToken().getToken().getTokenValue(), this.signing.id(), context -> context.token())).isPresent();
		String action = switch (workflow) {
			case DISABLE -> "user_disabled"; case ENABLE -> "user_enabled"; case PASSWORD -> "password_changed";
			case PASSWORD_RECOVERY -> "password_recovery_completed"; case TOTP_REPLACEMENT -> "totp_replacement_completed";
			case TOTP_RECOVERY -> "totp_recovery_completed"; case ADMIN_BOOTSTRAP -> "admin_bootstrap_completed"; case ADMIN_RECOVERY, ADMIN_CREDENTIAL_RECOVERY -> "admin_recovery_completed";
		};
		var owner = this.jdbc.sql("SELECT actor,source,correlation_id FROM iam_security_audit WHERE action=:action").param("action", action).query().singleRow();
		assertThat(revocationAudits()).hasSize(3).allSatisfy(row -> assertThat(row).containsAllEntriesOf(owner).containsEntry("target_user_id", this.userId)
				.containsEntry("target_type", "authorization").containsEntry("outcome", "success"));
		var after = prepared.codes().stream().map(this::stored).toList();
		for (String code : prepared.codes()) { rejection(request(code, authenticatedClient(code)), "invalid_grant"); }
		assertThat(prepared.codes().stream().map(this::stored).toList()).isEqualTo(after);
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='authorization_code_replayed'").query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@MethodSource("rollbackCases")
	void failedRevocationAuditsRollbackTheOwningSecurityChangeAndAllowTheSameProofToRetry(Workflow workflow, boolean deferred) {
		var prepared = prepare(workflow); var before = snapshot();
		fault("iam_security_audit", deferred ? "AFTER INSERT" : "BEFORE INSERT",
				"IF NEW.action='authorization_revoked' THEN " + (deferred ? "RAISE EXCEPTION 'isolated user revocation commit';" : "RETURN NULL;") + " END IF; RETURN NEW;", deferred);
		assertThatThrownBy(prepared.change()::run).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before); assertThat(revocationAudits()).isEmpty();
		this.jdbc.sql("DROP TRIGGER exchange_test_fault ON iam_security_audit").update(); this.jdbc.sql("DROP FUNCTION exchange_test_fault()").update();
		prepared.change().run(); prepared.codes().forEach(this::assertTerminal);
	}

	@Test
	void rejectedPasswordsAndNoOpStateChangesLeaveTheExistingApplicationGrantIntact() {
		String code = code(Set.of("openid", "offline_access")); var tokens = exchange(request(code, authenticatedClient(code))); var before = stored(code);
		assertThat(this.passwords.change(this.userId, this.sessionId, 1, this.authenticatedAt, "incorrect password", REPLACEMENT_PASSWORD, passwordContext()))
				.isEqualTo(IdentityPasswords.Result.INVALID_CREDENTIALS);
		assertThat(this.states.enable(this.userId, AUDIT)).isEqualTo(IdentityUserStates.Result.UNCHANGED);
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationAudits()).isEmpty();
		assertThat(this.online.use(tokens.getAccessToken().getTokenValue(), this.signing.id(), context -> context.token())).isPresent();
	}

	@Test
	void lastAdministratorProtectionAlsoPreservesExistingApplicationGrants() {
		prepareAdministrator(); freshSession(); String code = currentCode(this.userId, this.sessionId, Set.of("openid", "offline_access"));
		exchange(request(code, authenticatedClient(code))); var before = stored(code);
		assertThat(this.states.disable(this.userId, AUDIT)).isEqualTo(IdentityUserStates.Result.LAST_ADMINISTRATOR_PROTECTED);
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationAudits()).isEmpty();
	}

	@Test
	void normalBrowserLogoutKeepsTheSeparateApplicationGrant() {
		String code = code(Set.of("openid", "offline_access")); var tokens = exchange(request(code, authenticatedClient(code))); var before = stored(code);
		this.context.getBean(IdentityBrowserSessions.class).delete(this.sessionId, this.userId, () -> this.store.deleteById(this.sessionId));
		assertThat(stored(code)).isEqualTo(before); assertThat(revocationAudits()).isEmpty();
		assertThat(this.online.use(tokens.getAccessToken().getTokenValue(), this.signing.id(), context -> context.token())).isPresent();
	}

	@Test
	void aRefreshWaitingOnPasswordRecoveryCannotReturnANewTokenAfterRecoveryCommits() throws Exception {
		var proof = this.passwordRecoveries.issue(this.userId, AUDIT); String code = code(Set.of("openid", "offline_access"));
		var tokens = exchange(request(code, authenticatedClient(code)));
		var request = new OAuth2RefreshTokenAuthenticationToken(tokens.getRefreshToken().getTokenValue(), refreshClient(this.clientId, this.secret), Set.of(), Map.of());
		var provider = new IdentityRefreshTokenProvider(this.applications, this.authorizations, this.bindings, this.refresh, this.keys, this.audits, this.transactions);
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					this.users.lockById(this.userId); locked.countDown(); awaitLatch(release);
					// The trusted composition entry joins this transaction; its public limited entry remains independent.
					return this.passwordRecoveries.completeInTransaction(this.userId, proof.token(), REPLACEMENT_PASSWORD,
							new SecurityAuditContext("anonymous", "internal:user-revocation", UUID.randomUUID()));
				}));
				awaitLatch(locked);
				var reader = executor.submit(() -> {
					serverContext("https://iam.example");
					try { return catchThrowableOfType(OAuth2AuthenticationException.class, () -> provider.authenticate(request)); }
					finally { AuthorizationServerContextHolder.resetContext(); }
				});
				awaitUserWait(); release.countDown();
				assertThat(writer.get(10, TimeUnit.SECONDS)).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
				assertThat(reader.get(10, TimeUnit.SECONDS)).isNotNull().satisfies(ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_grant"));
				assertTerminal(code);
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void anAuthorizationRequestWaitingOnDisableAndEnableCannotReviveItsOldBrowserEvidence() throws Exception {
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					this.users.lockById(this.userId); locked.countDown(); awaitLatch(release);
					assertThat(this.states.disable(this.userId, AUDIT)).isEqualTo(IdentityUserStates.Result.CHANGED);
					return this.states.enable(this.userId, AUDIT);
				}));
				awaitLatch(locked);
				var reader = executor.submit(() -> {
					serverContext("https://iam.example");
					try { return catchThrowableOfType(OAuth2AuthenticationException.class, () -> code(Set.of("openid"))); }
					finally { AuthorizationServerContextHolder.resetContext(); }
				});
				awaitUserWait(); release.countDown();
				assertThat(writer.get(10, TimeUnit.SECONDS)).isEqualTo(IdentityUserStates.Result.CHANGED);
				assertThat(reader.get(10, TimeUnit.SECONDS)).isNotNull();
				assertThat(this.jdbc.sql("SELECT count(*) FROM iam_authorization_binding").query(Long.class).single()).isZero();
			}
			finally { release.countDown(); }
		}
	}

	private Prepared prepare(Workflow workflow) {
		Runnable change = switch (workflow) {
			case DISABLE -> () -> assertThat(this.states.disable(this.userId, AUDIT)).isEqualTo(IdentityUserStates.Result.CHANGED);
			case ENABLE -> () -> assertThat(this.states.enable(this.userId, AUDIT)).isEqualTo(IdentityUserStates.Result.CHANGED);
			case PASSWORD -> () -> assertThat(this.passwords.change(this.userId, this.sessionId, 1, this.authenticatedAt, PASSWORD, REPLACEMENT_PASSWORD, passwordContext())).isEqualTo(IdentityPasswords.Result.CHANGED);
			case PASSWORD_RECOVERY -> {
				var proof = this.passwordRecoveries.issue(this.userId, AUDIT);
				yield () -> assertThat(this.passwordRecoveries.complete(this.userId, proof.token(), REPLACEMENT_PASSWORD, "internal:user-revocation", UUID.randomUUID())).isEqualTo(IdentityPasswordRecoveries.Result.COMPLETED);
			}
			case TOTP_REPLACEMENT -> {
				var factor = activeFactor(); var pending = this.replacements.begin(this.userId, PASSWORD, freshTotp(factor), totpContext()).orElseThrow();
				yield () -> assertThat(this.replacements.complete(this.userId, pending.replacementId(), pending.token(), otp(pending.enrollment(), step()), totpContext())).isPresent();
			}
			case TOTP_RECOVERY -> {
				var factor = activeFactor(); var codes = this.recoveryCodes.issue(this.userId, freshTotp(factor), totpContext()).orElseThrow();
				var pending = this.factorRecoveries.begin(this.userId, PASSWORD, codes.codes().getFirst(), recoveryContext()).orElseThrow();
				yield () -> assertThat(this.factorRecoveries.complete(this.userId, pending.recoveryId(), pending.token(), otp(pending.enrollment(), step()), totpContext())).isPresent();
			}
			case ADMIN_BOOTSTRAP -> {
				var factor = this.administrators.prepareCandidate(this.userId, PASSWORD, totpContext()).orElseThrow().enrollment().orElseThrow();
				yield () -> assertThat(this.administrators.bootstrap(this.userId, factor.factorId(), PASSWORD, otp(factor, step()), totpContext())).isPresent();
			}
			case ADMIN_RECOVERY -> {
				prepareAdministrator(); freshSession();
				var audit = deploymentAudit(); var pending = this.administratorRecoveries.begin(this.userId, PASSWORD, audit).orElseThrow();
				yield () -> assertThat(this.administratorRecoveries.complete(this.userId, pending.recoveryId(), pending.token(), PASSWORD, otp(pending.enrollment(), step()), audit)).isPresent();
			}
			case ADMIN_CREDENTIAL_RECOVERY -> {
				prepareAdministrator(); freshSession();
				var audit = new SecurityAuditContext("deployment:operator", "deployment:admin-credentials:CHANGE-123", UUID.randomUUID());
				var pending = this.credentialRecoveries.begin(this.userId, audit).orElseThrow();
				yield () -> assertThat(this.credentialRecoveries.complete(this.userId, pending.recoveryId(), pending.token(), REPLACEMENT_PASSWORD, otp(pending.enrollment(), step()), audit)).isPresent();
			}
		};
		var codes = List.of(currentCode(this.userId, this.sessionId, Set.of("openid", "profile")),
				currentCode(this.userId, this.sessionId, Set.of("openid", "offline_access")), currentCode(this.userId, this.sessionId, Set.of("openid")));
		for (String code : codes.subList(0, 2)) { exchange(request(code, authenticatedClient(code))); }
		UUID otherUser = activeUser("bobby"); String otherCode = currentCode(otherUser, browserSession(otherUser, this.authenticatedAt), Set.of("openid", "offline_access"));
		exchange(request(otherCode, authenticatedClient(otherCode)));
		if (workflow == Workflow.ENABLE) {
			// Model a pre-integration disabled account whose unchanged credential epoch would otherwise resurrect its grants.
			this.jdbc.sql("UPDATE iam_user SET status='disabled' WHERE id=:id").param("id", this.userId).update();
		}
		return new Prepared(change, codes, otherCode);
	}

	private void prepareAdministrator() {
		var factor = this.administrators.prepareCandidate(this.userId, PASSWORD, totpContext()).orElseThrow().enrollment().orElseThrow();
		assertThat(this.administrators.bootstrap(this.userId, factor.factorId(), PASSWORD, otp(factor, step()), totpContext())).isPresent();
	}

	private void freshSession() {
		this.sessionId = browserSession(this.userId, this.authenticatedAt);
		sessionAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, version(this.userId));
	}

	private String currentCode(UUID owner, String session, Set<String> scopes) {
		var browser = UsernamePasswordAuthenticationToken.authenticated(owner, null, List.of());
		var request = new OAuth2AuthorizationCodeRequestAuthenticationToken("https://iam.example/oauth2/authorize", this.clientId.toString(), browser,
				REDIRECT, "opaque-client-state", scopes, Map.of("code_challenge", CHALLENGE, "code_challenge_method", "S256", "nonce", NONCE));
		request.setDetails(new IdentityAuthorizationRequestProvider.BrowserEvidence(session, this.authenticatedAt, version(owner), UUID.randomUUID()));
		return ((OAuth2AuthorizationCodeRequestAuthenticationToken) this.requests.authenticate(request)).getAuthorizationCode().getTokenValue();
	}

	private void assertTerminal(String code) {
		var authorization = stored(code).authorization(); assertThat(IdentityAuthorizations.isRevoked(authorization)).isTrue();
		assertThat(authorization.getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		if (authorization.getAccessToken() != null) {
			assertThat(authorization.getAccessToken().isInvalidated()).isTrue(); assertThat(authorization.getToken(OidcIdToken.class).isInvalidated()).isTrue();
			assertThat(this.online.use(authorization.getAccessToken().getToken().getTokenValue(), this.signing.id(), context -> context.token())).isEmpty();
		}
		if (authorization.getRefreshToken() != null) {
			assertThat(authorization.getRefreshToken().isInvalidated()).isTrue();
			assertThat(this.refresh.findByAuthorization(authorization)).get().satisfies(family -> assertThat(family.status()).isEqualTo(IdentityRefreshFamily.Status.REVOKED));
		}
	}

	private IdentityTotpEnrollment activeFactor() {
		for (int attempt = 0; attempt < 10; attempt++) {
			var factor = this.totps.beginEnrollment(this.userId, AUDIT); long step = step();
			if (Stream.of(step - 1, step, step + 1, step + 2).map(value -> otp(factor, value)).distinct().count() == 4) {
				assertThat(this.totps.confirmEnrollment(this.userId, factor.factorId(), otp(factor, step), totpContext())).isTrue(); return factor;
			}
		}
		throw new AssertionError("Cannot create distinct adjacent factor codes");
	}

	private String freshTotp(IdentityTotpEnrollment factor) {
		long last = this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single();
		return otp(factor, Math.max(step(), last + 1));
	}

	private long version(UUID owner) { return this.jdbc.sql("SELECT credential_version FROM iam_password WHERE user_id=:id").param("id", owner).query(Long.class).single(); }
	private long step() { return this.jdbc.sql("SELECT floor(extract(epoch FROM clock_timestamp()) / 30)::BIGINT").query(Long.class).single(); }
	private List<List<String>> snapshot() { return SNAPSHOT_TABLES.stream().map(table -> this.jdbc.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList(); }
	private List<Map<String, Object>> revocationAudits() { return this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='authorization_revoked' ORDER BY recorded_at,id").query().listOfRows(); }
	private void awaitUserWait() { await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%iam_user%FOR%')").query(Boolean.class).single()); }
	private static Stream<Object[]> rollbackCases() { return Stream.of(Workflow.values()).flatMap(workflow -> Stream.of(new Object[] { workflow, false }, new Object[] { workflow, true })); }
	private static TotpAuthenticationContext totpContext() { return new TotpAuthenticationContext("internal:user-revocation", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static MfaRecoveryCodeContext recoveryContext() { return new MfaRecoveryCodeContext("internal:user-revocation", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static PasswordAuthenticationContext passwordContext() { return new PasswordAuthenticationContext("internal:user-revocation", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static SecurityAuditContext deploymentAudit() { return new SecurityAuditContext("deployment:operator", "deployment:admin-recovery:CHANGE-123", UUID.randomUUID()); }

	private static String otp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8]; for (int index = 7; index >= 0; index--) { counter[index] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest()); mac.init(new KeyParameter(Base32.decode(factor.secret()))); mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()]; mac.doFinal(hash, 0); int offset = hash[19] & 15;
		int binary = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(Locale.ROOT, "%06d", binary % 1_000_000);
	}

	private static Path totpKey() {
		try {
			Path path = Files.createTempFile("iam-user-revocation-totp-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

	private enum Workflow { DISABLE, ENABLE, PASSWORD, PASSWORD_RECOVERY, TOTP_REPLACEMENT, TOTP_RECOVERY, ADMIN_BOOTSTRAP, ADMIN_RECOVERY, ADMIN_CREDENTIAL_RECOVERY }
	private record Prepared(Runnable change, List<String> codes, String otherCode) { }

}
