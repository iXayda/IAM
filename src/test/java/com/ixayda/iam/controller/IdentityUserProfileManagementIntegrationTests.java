package com.ixayda.iam.controller;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.TotpTestSupport;
import com.ixayda.iam.dto.IdentityUserProfileUpdateRequest;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityTotpEnrollment;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.security.BrowserHttpTestSupport;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityUserProfileManagement;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "iam.browser.requests-per-second=1000")
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserProfileManagementIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:user-profile-test", "internal:test", UUID.randomUUID());
	private static final Path KEY_FILE = keyFile();
	@Autowired IdentityAdministrators administrators;
	@Autowired IdentityUsers users;
	@Autowired IdentityUserSetups setups;
	@Autowired IdentityUserProfileManagement profiles;
	@Autowired JdbcClient jdbc;
	@Autowired PlatformTransactionManager transactions;

	@DynamicPropertySource
	static void totpKey(DynamicPropertyRegistry properties) {
		properties.add("iam.totp.key-file", KEY_FILE::toString);
		properties.add("iam.totp.cleanup-ms", () -> 3_600_000);
	}

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE iam_user, iam_browser_session, iam_security_audit, iam_password_authentication_limit, iam_totp_authentication_limit, iam_mfa_recovery_limit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
	}

	@ParameterizedTest
	@ValueSource(strings = { "active", "pending", "disabled", "self" })
	void administratorUpdatesOnlyTheDisplayNameWithAttributionAndUnchangedAuthentication(String state) throws Exception {
		var factor = administrator();
		var target = state.equals("self") ? this.users.findById(factor.userId()).orElseThrow() : state.equals("pending") ? this.users.create("bobby", "Bob", SYSTEM) : activeUser();
		if (state.equals("disabled")) { this.jdbc.sql("UPDATE iam_user SET status='disabled' WHERE id=:id").param("id", target.id()).update(); }
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var management = attribute(session, IdentityAdministratorSessions.AUTHENTICATION);
			var passwordTime = attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT);
			String oldHash = this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id=:id").param("id", factor.userId()).query(String.class).single();
			var response = update(client, session, target.id(), "Cafe\u0301", freshCode(factor));
			assertThat(response.statusCode()).isEqualTo(204); assertSecurityHeaders(response);
			var updated = this.users.findById(target.id()).orElseThrow();
			assertThat(updated.displayName()).isEqualTo("Caf\u00e9"); assertThat(updated.username()).isEqualTo(target.username());
			assertThat(updated.status()).isEqualTo(state.equals("disabled") ? IdentityUser.Status.DISABLED : target.status());
			assertThat(attribute(session, IdentityAdministratorSessions.AUTHENTICATION)).isEqualTo(management);
			assertThat(attribute(session, IdentityBrowserSessions.AUTHENTICATED_AT)).isEqualTo(passwordTime);
			assertThat(get(client, "/api/admin/me", session).statusCode()).isEqualTo(200);
			assertThat(this.jdbc.sql("SELECT password_hash FROM iam_password WHERE user_id=:id").param("id", factor.userId()).query(String.class).single()).isEqualTo(oldHash);
			var audit = this.jdbc.sql("SELECT * FROM iam_security_audit WHERE action='user_profile_updated'").query().singleRow();
			assertThat(audit).containsEntry("actor", "user:" + factor.userId()).containsEntry("target_user_id", target.id()).containsEntry("source", "browser:admin-user-profile");
			assertThat(audit.toString()).doesNotContain("Caf", freshCode(factor), PASSWORD);
		}
	}

	@Test
	void unchangedDisplayNameStillRequiresAndConsumesFreshTotp() throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor); String code = freshCode(factor);
			assertThat(update(client, session, target.id(), target.displayName(), code).statusCode()).isEqualTo(204);
			assertThat(update(client, session, target.id(), "Changed", code).statusCode()).isEqualTo(400);
			assertThat(events()).isZero();
		}
	}

	@Test
	void missingUserIsOnlyReportedAfterFreshCodeVerification() throws Exception {
		var factor = administrator();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor); UUID missing = UUID.randomUUID();
			assertThat(update(client, session, missing, "Name", "invalid").statusCode()).isEqualTo(400);
			String code = freshCode(factor);
			assertThat(update(client, session, missing, "Name", code).statusCode()).isEqualTo(404);
			assertThat(update(client, session, missing, "Name", code).statusCode()).isEqualTo(400);
			assertThat(events()).isZero();
		}
	}

	@Test
	void anonymousOrdinaryAndPasswordOnlyRequestsCannotUpdateProfiles() throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			var csrf = get(client, "/api/csrf", null);
			assertThat(post(client, path(target.id()), cookie(csrf), form("Changed", freshCode(factor), csrf(csrf))).statusCode()).isEqualTo(401);
			assertThat(update(client, login(client, "bobby"), target.id(), "Changed", freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(update(client, login(client, "alice"), target.id(), "Changed", freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(this.users.findById(target.id())).contains(target); assertThat(events()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", "name\n", "\u0000", "long" })
	void invalidDisplayNamesCannotChangeProfiles(String displayName) throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertThat(update(client, session, target.id(), displayName.equals("long") ? "😀".repeat(129) : displayName, freshCode(factor)).statusCode()).isEqualTo(400);
			assertThat(this.users.findById(target.id())).contains(target); assertThat(events()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "&displayName=Other", "&code=000000", "&actor=system", "&userId=other", "&username=other", "&_csrf=duplicate" })
	void duplicateAndUnapprovedFieldsAreRejected(String extra) throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var response = post(client, path(target.id()), session, form("Changed", freshCode(factor), csrf(get(client, "/api/csrf", session))) + extra);
			assertThat(response.statusCode()).isEqualTo(400); assertThat(this.users.findById(target.id())).contains(target);
		}
	}

	@Test
	void csrfQueryMethodAndContentTypeBoundariesAreEnforced() throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			assertThat(post(client, path(target.id()), session, "displayName=Changed&code=" + freshCode(factor)).statusCode()).isEqualTo(403);
			assertThat(post(client, path(target.id()) + "?extra=value", session, form("Changed", freshCode(factor), csrf(get(client, "/api/csrf", session)))).statusCode()).isEqualTo(400);
			assertThat(get(client, path(target.id()), session).statusCode()).isEqualTo(403);
			var json = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path(target.id()))).header("Cookie", session).header("Content-Type", "application/json")
					.POST(HttpRequest.BodyPublishers.ofString("{}")).build();
			assertThat(client.send(json, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
			assertThat(this.users.findById(target.id())).contains(target); assertThat(events()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "membership", "version", "factor", "session", "expired" })
	void serviceRechecksCurrentAuthorityAndSessionInsteadOfTrustingCapturedEvidence(String changed) throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor); var evidence = evidence(factor, session);
			switch (changed) {
				case "membership" -> this.jdbc.sql("DELETE FROM iam_administrator").update();
				case "version" -> this.jdbc.sql("UPDATE iam_password SET credential_version=credential_version+1 WHERE user_id=:id").param("id", factor.userId()).update();
				case "factor" -> this.jdbc.sql("DELETE FROM iam_user_totp").update();
				case "session" -> this.jdbc.sql("DELETE FROM iam_browser_session").update();
				case "expired" -> evidence = new IdentityAdministratorContext(evidence.actorId(), evidence.sessionId(), evidence.credentialVersion(), 1, evidence.management(), evidence.authentication());
			}
			var result = this.profiles.updateDisplayName(evidence, target.id(), "Changed", freshCode(factor), () -> {});
			assertThat(result).isIn(IdentityUserProfileManagement.Status.INVALID_SESSION, IdentityUserProfileManagement.Status.FORBIDDEN);
			assertThat(this.users.findById(target.id())).contains(target); assertThat(events()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "audit", "persistence", "late-authority" })
	void failedAuditSessionSaveOrFinalAuthorityCheckRollsBackProfileAndTotpConsumption(String fault) throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor); var evidence = evidence(factor, session);
			long before = step(factor);
			if (fault.equals("audit")) { this.jdbc.sql("ALTER TABLE iam_security_audit ADD CONSTRAINT profile_audit_fault CHECK (action<>'user_profile_updated')").update(); }
			try {
				assertThatThrownBy(() -> this.profiles.updateDisplayName(evidence, target.id(), "Changed", freshCode(factor), () -> {
					if (fault.equals("persistence")) { throw new IllegalStateException("Save failed"); }
					if (fault.equals("late-authority")) { this.jdbc.sql("DELETE FROM iam_administrator").update(); }
				})).isInstanceOf(RuntimeException.class);
			}
			finally { if (fault.equals("audit")) { this.jdbc.sql("ALTER TABLE iam_security_audit DROP CONSTRAINT profile_audit_fault").update(); } }
			assertThat(this.users.findById(target.id())).contains(target); assertThat(step(factor)).isEqualTo(before); assertThat(events()).isZero();
		}
	}

	@ParameterizedTest
	@ValueSource(booleans = { false, true })
	void renewalAfterOriginalIdleExpiryRollsBackTheProfileAndTotp(boolean self) throws Exception {
		var factor = administrator();
		var target = self ? this.users.findById(factor.userId()).orElseThrow() : activeUser();
		try (var client = client()) {
			String session = elevate(client, login(client, "alice"), factor);
			var evidence = evidence(factor, session);
			long before = step(factor);
			long deadline = System.currentTimeMillis() + 1500;
			this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
					.param("expiry", deadline).param("id", evidence.sessionId()).update();
			assertThatIllegalStateException().isThrownBy(() -> this.profiles.updateDisplayName(evidence, target.id(), "Changed",
					freshCode(factor), () -> {
						await().atMost(Duration.ofSeconds(5)).until(() -> System.currentTimeMillis() > deadline);
						this.jdbc.sql("UPDATE iam_browser_session SET expiry_time = :expiry, last_access_time = :expiry - max_inactive_interval * 1000 WHERE session_id = :id")
								.param("expiry", deadline + 60_000).param("id", evidence.sessionId()).update();
					}));
			assertThat(this.users.findById(target.id())).contains(target);
			assertThat(step(factor)).isEqualTo(before);
			assertThat(events()).isZero();
			assertThat(this.jdbc.sql("SELECT expiry_time FROM iam_browser_session WHERE session_id = :id")
					.param("id", evidence.sessionId()).query(Long.class).single()).isEqualTo(deadline);
		}
	}

	@Test
	void concurrentUpdatesCannotReuseOneTotpAndCallerTransactionsAreRejected() throws Exception {
		var factor = administrator(); var target = activeUser();
		try (var client = client(); var executor = Executors.newFixedThreadPool(2)) {
			String session = elevate(client, login(client, "alice"), factor); var context = evidence(factor, session); String code = freshCode(factor);
			var start = new CountDownLatch(1);
			var one = executor.submit(() -> { start.await(); return this.profiles.updateDisplayName(context, target.id(), "One", code, () -> {}); });
			var two = executor.submit(() -> { start.await(); return this.profiles.updateDisplayName(context, target.id(), "Two", code, () -> {}); });
			start.countDown();
			assertThat(List.of(one.get(20, TimeUnit.SECONDS), two.get(20, TimeUnit.SECONDS))).containsExactlyInAnyOrder(IdentityUserProfileManagement.Status.UPDATED, IdentityUserProfileManagement.Status.REJECTED);
			assertThat(events()).isEqualTo(1);
			assertThatThrownBy(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> this.profiles.updateDisplayName(context, target.id(), "Other", code, () -> {}))).isInstanceOf(IllegalStateException.class);
			assertThat(new IdentityUserProfileUpdateRequest("Private", "123456").toString()).doesNotContain("Private", "123456");
		}
	}

	private IdentityAdministratorContext evidence(IdentityTotpEnrollment factor, String cookie) {
		return new IdentityAdministratorContext(factor.userId(), cookie.substring(cookie.indexOf('=') + 1), (Long) attribute(cookie, IdentityBrowserSessions.CREDENTIAL_VERSION),
				(Long) attribute(cookie, IdentityBrowserSessions.AUTHENTICATED_AT), (IdentityAdministratorAuthentication) attribute(cookie, IdentityAdministratorSessions.AUTHENTICATION), context());
	}
	private Object attribute(String cookie, String name) {
		return SerializationUtils.deserialize(this.jdbc.sql("SELECT a.attribute_bytes FROM iam_browser_session_attributes a JOIN iam_browser_session s ON s.primary_id=a.session_primary_id WHERE s.session_id=:id AND a.attribute_name=:name")
				.param("id", cookie.substring(cookie.indexOf('=') + 1)).param("name", name).query(byte[].class).single());
	}
	private long step(IdentityTotpEnrollment factor) { return this.jdbc.sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id").param("id", factor.userId()).query(Long.class).single(); }
	private long events() { return this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action='user_profile_updated'").query(Long.class).single(); }
	private static String path(UUID id) { return "/api/admin/users/" + id + "/profile"; }
	private HttpResponse<String> update(HttpClient client, String session, UUID target, String displayName, String code) throws Exception { return post(client, path(target), session, form(displayName, code, csrf(get(client, "/api/csrf", session)))); }
	private static String form(String displayName, String code, String csrf) { return "displayName=" + encode(displayName) + "&code=" + encode(code) + "&_csrf=" + encode(csrf); }
	private IdentityUser activeUser() {
		var user = this.users.create("bobby", "Private Name", SYSTEM); var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:test", UUID.randomUUID()); return this.users.findById(user.id()).orElseThrow();
	}
	private IdentityTotpEnrollment administrator() {
		UUID id = this.administrators.createCandidate("alice", "Alice", PASSWORD, SYSTEM);
		var factor = TotpTestSupport.distinctEnrollment(() ->
				this.administrators.prepareCandidate(id, PASSWORD, context()).orElseThrow().enrollment().orElseThrow());
		this.administrators.bootstrap(id, factor.factorId(), PASSWORD, otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)), context()).orElseThrow();
		this.jdbc.sql("UPDATE iam_user_totp SET last_used_step=last_used_step-1 WHERE user_id=:id").param("id", id).update(); return factor;
	}
	private String login(HttpClient client, String username) throws Exception {
		var csrf = get(client, "/api/csrf", null); var response = post(client, "/login", cookie(csrf), credentials(username, PASSWORD, csrf(csrf)));
		assertThat(response.statusCode()).isEqualTo(204); return cookie(response);
	}
	private String elevate(HttpClient client, String cookie, IdentityTotpEnrollment factor) throws Exception {
		var response = post(client, "/admin/mfa", cookie, "code=" + otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30)) + "&_csrf=" + encode(csrf(get(client, "/api/csrf", cookie))));
		assertThat(response.statusCode()).isEqualTo(204); return cookie(response);
	}
	private static TotpAuthenticationContext context() { return new TotpAuthenticationContext("internal:test", InetAddress.getLoopbackAddress(), UUID.randomUUID()); }
	private static Path keyFile() {
		try { Path path = Files.createTempFile("iam-user-profile-", ".key"); byte[] key = new byte[32]; new SecureRandom().nextBytes(key); Files.write(path, key); path.toFile().deleteOnExit(); return path; }
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}
	private static String freshCode(IdentityTotpEnrollment factor) { return otp(factor, Math.floorDiv(Instant.now().getEpochSecond(), 30) + 1); }
	private static String otp(IdentityTotpEnrollment factor, long step) { return TotpTestSupport.otp(factor, step); }
}
