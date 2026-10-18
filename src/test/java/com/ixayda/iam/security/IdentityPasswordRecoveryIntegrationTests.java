package com.ixayda.iam.security;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAuthentications;
import com.ixayda.iam.service.IdentityPasswordRecoveries;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static com.ixayda.iam.service.IdentityPasswordRecoveries.Result.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(PostgreSqlTestConfiguration.class)
class IdentityPasswordRecoveryIntegrationTests extends BrowserHttpTestSupport {

	private static final String PASSWORD = "Seven amber lanterns beside the river";
	private static final String NEW_PASSWORD = "New violet lanterns above the lake";
	private static final String SOURCE = "internal:recovery-test";
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:recovery-test", SOURCE, UUID.randomUUID());

	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityPasswordRecoveries recoveries;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private SessionRepository<?> repository;
	@MockitoSpyBean
	private IdentityAuthentications authentications;

	@BeforeEach
	@AfterEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_recovery",
				"iam_password_authentication_limit", "iam_security_audit", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void recoveryRevokesRealBrowserSessionsAndRequiresNormalLoginWithTheNewPassword() throws Exception {
		UUID alice = activeUser("alice");
		activeUser("bobby");
		try (var client = client()) {
			String first = login(client, "alice", PASSWORD);
			String second = login(client, "alice", PASSWORD);
			String bob = login(client, "bobby", PASSWORD);
			Session loaded = this.repository.findById(first.split("=", 2)[1]);
			var proof = this.recoveries.issue(alice, SYSTEM);
			// Issuance alone does not log the user out or change the current credential.
			assertThat(get(client, "/api/me", first).statusCode()).isEqualTo(200);
			assertThat(this.recoveries.complete(alice, proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(COMPLETED);
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", alice.toString())
					.query(Long.class).single()).isZero();
			for (String cookie : List.of(first, second)) {
				var rejected = get(client, "/api/me", cookie);
				assertThat(rejected.statusCode()).isEqualTo(401);
				assertSecurityHeaders(rejected);
				assertThat(rejected.body()).doesNotContain(alice.toString(), PASSWORD, NEW_PASSWORD, proof.token());
			}
			assertThat(get(client, "/api/me", bob).statusCode()).isEqualTo(200);
			assertThatThrownBy(() -> save(loaded)).isInstanceOf(IllegalStateException.class);
			var page = get(client, "/api/csrf", null);
			assertThat(post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page))).statusCode()).isEqualTo(401);
			assertThat(get(client, "/api/me", login(client, "alice", NEW_PASSWORD)).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void oldPasswordAuthenticationCannotCreateASessionAfterRecovery() throws Exception {
		UUID alice = activeUser("alice");
		var proof = this.recoveries.issue(alice, SYSTEM);
		var verified = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var client = client(); var executor = Executors.newSingleThreadExecutor()) {
			var page = get(client, "/api/csrf", null);
			doAnswer(call -> {
				Object result = call.callRealMethod();
				verified.countDown();
				assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
				return result;
			}).when(this.authentications).authenticate(eq("alice"), eq(PASSWORD), any());
			var pending = executor.submit(() -> post(client, "/login", cookie(page), credentials("alice", PASSWORD, csrf(page))));
			try {
				assertThat(verified.await(10, TimeUnit.SECONDS)).isTrue();
				assertThat(this.recoveries.complete(alice, proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(COMPLETED);
			}
			finally { release.countDown(); }
			var rejected = pending.get(10, TimeUnit.SECONDS);
			assertThat(rejected.statusCode()).isEqualTo(503);
			assertThat(rejected.headers().allValues("Set-Cookie")).isEmpty();
			assertThat(rejected.headers().firstValue("Location")).isEmpty();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session WHERE principal_name = :id").param("id", alice.toString())
					.query(Long.class).single()).isZero();
			assertThat(this.jdbc.sql("SELECT count(*) FROM iam_security_audit WHERE action = 'browser_session_created'").query(Long.class).single()).isZero();
			assertThat(get(client, "/api/me", login(client, "alice", NEW_PASSWORD)).statusCode()).isEqualTo(200);
		}
	}

	@Test
	void recoveryDoesNotBypassOrExtendThePasswordLoginLimit() throws Exception {
		UUID alice = activeUser("alice");
		var proof = this.recoveries.issue(alice, SYSTEM);
		try (var client = client()) {
			var page = get(client, "/api/csrf", null);
			for (int i = 0; i < 10; i++) {
				assertThat(post(client, "/login", cookie(page), credentials("alice", "wrong", csrf(page))).statusCode()).isEqualTo(401);
			}
			var before = this.jdbc.sql("SELECT to_jsonb(t)::text FROM iam_password_authentication_limit t ORDER BY dimension").query(String.class).list();
			assertThat(this.recoveries.complete(alice, proof.token(), NEW_PASSWORD, SOURCE, UUID.randomUUID())).isEqualTo(COMPLETED);
			assertThat(this.jdbc.sql("SELECT to_jsonb(t)::text FROM iam_password_authentication_limit t ORDER BY dimension").query(String.class).list()).isEqualTo(before);
			assertThat(post(client, "/login", cookie(page), credentials("alice", NEW_PASSWORD, csrf(page))).statusCode()).isEqualTo(401);
			this.jdbc.sql("UPDATE iam_password_authentication_limit SET window_started_at = clock_timestamp() - INTERVAL '1 hour'").update();
			assertThat(get(client, "/api/me", login(client, "alice", NEW_PASSWORD)).statusCode()).isEqualTo(200);
		}
	}

	private UUID activeUser(String name) {
		var user = this.users.create(name, "Alice", SYSTEM);
		var setup = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), setup.token(), PASSWORD, SOURCE, UUID.randomUUID());
		return user.id();
	}

	private String login(java.net.http.HttpClient client, String name, String password) throws Exception {
		var page = get(client, "/api/csrf", null);
		var response = post(client, "/login", cookie(page), credentials(name, password, csrf(page)));
		assertThat(response.statusCode()).isEqualTo(204);
		assertThat(response.headers().firstValue("Location")).isEmpty();
		return cookie(response);
	}

	@SuppressWarnings("unchecked")
	private void save(Session session) { ((SessionRepository<Session>) this.repository).save(session); }

}
