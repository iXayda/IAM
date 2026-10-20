package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityApplicationAccess;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.junit.jupiter.api.AfterEach;
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

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityApplicationRolesIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final String PASSWORD = "Ceramic orchard quartz river 87";
	private static final SecurityAuditContext AUDIT = new SecurityAuditContext("system:application-roles-test", "internal:application-roles", UUID.randomUUID());
	@Autowired private IdentityApplicationRoles applications;
	@Autowired private IdentityProtocolClients protocol;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityUsers users;
	@Autowired private IdentityUserSetups setups;
	@Autowired private IdentityUserStates states;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityResourceRoles roles;
	@Autowired private IdentityUserRoles bindings;
	@Autowired private IdentitySigningKeys keys;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	private UUID userId;
	private UUID resourceId;
	private UUID roleId;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.signing.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.keys.initialize();
		this.userId = activeUser("alice");
		this.resourceId = this.resources.create("urn:example:orders", "Orders", AUDIT).id();
		this.roleId = this.roles.create(this.resourceId, "reader", "Reader", AUDIT).id();
	}

	@AfterEach
	void removeReferences() { this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user_role,iam_user_resource_role_revision CASCADE").update(); }

	@Test
	void onlyActiveUserAssignmentsAllowedForTheExactClientAndResourceBecomeRoles() {
		var permitted = this.roles.create(this.resourceId, "editor", "Editor", AUDIT);
		var unassigned = this.roles.create(this.resourceId, "unassigned", "Unassigned", AUDIT);
		var disallowed = this.roles.create(this.resourceId, "private", "Private", AUDIT);
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		this.bindings.change(this.userId, permitted.id(), 1, true, AUDIT);
		this.bindings.change(this.userId, disallowed.id(), 2, true, AUDIT);
		var client = client(this.resourceId, Set.of(this.roleId, permitted.id(), unassigned.id()));
		var before = snapshot();
		var access = project(this.userId, 1, client).orElseThrow();
		assertThat(access.userId()).isEqualTo(this.userId);
		assertThat(access.clientId()).isEqualTo(client.client().id());
		assertThat(access.resourceId()).isEqualTo(this.resourceId);
		assertThat(access.audience()).isEqualTo("urn:example:orders");
		assertThat(access.credentialVersion()).isEqualTo(1);
		assertThat(access.clientVersion()).isEqualTo(1);
		assertThat(access.resourceVersion()).isEqualTo(1);
		assertThat(access.assignmentVersion()).isEqualTo(3);
		assertThat(access.roles()).extracting(IdentityApplicationAccess.Role::code).containsExactly("editor", "reader");
		assertThat(access.roles()).extracting(IdentityApplicationAccess.Role::id).containsExactly(permitted.id(), this.roleId);
		assertThat(access.roles()).allSatisfy(role -> assertThat(role.version()).isEqualTo(1));
		assertThatThrownBy(() -> access.roles().clear()).isInstanceOf(UnsupportedOperationException.class);
		assertThat(access.toString()).doesNotContain("editor", "reader", this.userId.toString());
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void sameRoleCodeInAnotherResourceAndAssignmentsOfAnotherUserDoNotCrossBoundaries() {
		var anotherResource = this.resources.create("urn:example:billing", "Billing", AUDIT);
		var anotherRole = this.roles.create(anotherResource.id(), "reader", "Reader", AUDIT);
		UUID anotherUser = activeUser("bobby");
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		this.bindings.change(anotherUser, anotherRole.id(), 0, true, AUDIT);
		var orders = client(this.resourceId, Set.of(this.roleId));
		var billing = client(anotherResource.id(), Set.of(anotherRole.id()));
		assertThat(project(this.userId, 1, billing).orElseThrow().roles()).isEmpty();
		assertThat(project(anotherUser, 1, orders).orElseThrow().roles()).isEmpty();
		assertThat(project(this.userId, 1, orders).orElseThrow().roles()).extracting(IdentityApplicationAccess.Role::id).containsExactly(this.roleId);
		assertThat(project(anotherUser, 1, billing).orElseThrow().roles()).extracting(IdentityApplicationAccess.Role::id).containsExactly(anotherRole.id());
		assertThat(project(this.userId, 1, billing).orElseThrow().audience()).isEqualTo("urn:example:billing");
	}

	@Test
	void emptyAndRevokedAssignmentsRetainTheirExactRevisionWithoutInventingRoles() {
		var client = client(this.resourceId, Set.of(this.roleId));
		var empty = project(this.userId, 1, client).orElseThrow();
		assertThat(empty.roles()).isEmpty();
		assertThat(empty.assignmentVersion()).isZero();
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		assertThat(project(this.userId, 1, client).orElseThrow().roles()).hasSize(1);
		this.bindings.change(this.userId, this.roleId, 1, false, AUDIT);
		var revoked = project(this.userId, 1, client).orElseThrow();
		assertThat(revoked.roles()).isEmpty();
		assertThat(revoked.assignmentVersion()).isEqualTo(2);
	}

	@Test
	void inactiveRolesAreExcludedAndReenabledRolesHaveNewVersions() {
		var client = client(this.resourceId, Set.of(this.roleId));
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		this.roles.setEnabled(this.roleId, 1, false, AUDIT);
		assertThat(project(this.userId, 1, client).orElseThrow().roles()).isEmpty();
		this.roles.setEnabled(this.roleId, 2, true, AUDIT);
		assertThat(project(this.userId, 1, client).orElseThrow().roles()).singleElement().satisfies(role -> assertThat(role.version()).isEqualTo(3));
	}

	@ParameterizedTest
	@ValueSource(strings = { "pending", "disabled", "unknown", "credential", "client", "resource" })
	void inactiveOrStaleSubjectsAndCatalogStatesCannotProduceAnAccessContext(String invalid) {
		var client = client(this.resourceId, Set.of(this.roleId));
		UUID subject = this.userId;
		long credential = 1;
		switch (invalid) {
			case "pending" -> subject = this.users.create("pending", "Pending", AUDIT).id();
			case "disabled" -> this.states.disable(this.userId, AUDIT);
			case "unknown" -> subject = UUID.randomUUID();
			case "credential" -> credential = 2;
			case "client" -> this.clients.setEnabled(client.client().id(), 1, false, AUDIT);
			default -> this.resources.setEnabled(this.resourceId, 1, false, AUDIT);
		}
		var before = snapshot();
		assertThat(project(subject, credential, client)).isEmpty();
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void allOneHundredAllowedRolesAreProjectedBeyondAdministrativePagination() {
		var ids = new java.util.HashSet<UUID>();
		for (int index = 0; index < 100; index++) {
			UUID role = this.roles.create(this.resourceId, "role_" + String.format(java.util.Locale.ROOT, "%03d", index), "Role " + index, AUDIT).id();
			ids.add(role); this.bindings.change(this.userId, role, index, true, AUDIT);
		}
		var client = client(this.resourceId, ids);
		assertThat(this.bindings.search(this.userId, this.resourceId, 20, null).items()).hasSize(20);
		var projection = project(this.userId, 1, client).orElseThrow();
		assertThat(projection.roles()).hasSize(100);
		assertThat(projection.assignmentVersion()).isEqualTo(100);
		assertThat(projection.roles()).extracting(IdentityApplicationAccess.Role::id).containsExactlyInAnyOrderElementsOf(ids);
	}

	@Test
	void anApplicationRoleNamedAdminNeverCreatesIamAdministratorMembership() {
		var role = this.roles.create(this.resourceId, "admin", "Application admin", AUDIT);
		this.bindings.change(this.userId, role.id(), 0, true, AUDIT);
		var access = project(this.userId, 1, client(this.resourceId, Set.of(role.id()))).orElseThrow();
		assertThat(access.roles()).extracting(IdentityApplicationAccess.Role::code).containsExactly("admin");
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_administrator WHERE user_id=:id").param("id", this.userId).query(Long.class).single()).isZero();
	}

	@Test
	void projectionRequiresAnExistingWritableTransactionAndLeavesNoStateAfterRollback() {
		var client = client(this.resourceId, Set.of(this.roleId));
		assertThatThrownBy(() -> this.applications.projectForIssuance(this.userId, 1, client)).isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
		var readonly = new TransactionTemplate(this.transactions); readonly.setReadOnly(true);
		assertThatIllegalStateException().isThrownBy(() -> readonly.execute(tx -> this.applications.projectForIssuance(this.userId, 1, client)));
		var before = snapshot();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			assertThat(this.applications.projectForIssuance(this.userId, 1, client)).isPresent();
			tx.setRollbackOnly();
		});
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void aRoleReadPermissionFailureCannotProduceAPartialOrEmptySuccessContext() {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var client = client(this.resourceId, Set.of(this.roleId));
		var before = snapshot();
		String role = "application_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role).update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT ON ALL TABLES IN SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT UPDATE ON iam_signing_key_state,iam_user,iam_resource,iam_resource_role,iam_client,oauth2_registered_client TO " + role).update();
			this.jdbc.sql("REVOKE SELECT ON iam_user_role FROM " + role).update();
			assertThatThrownBy(() -> new TransactionTemplate(this.transactions).execute(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + role).update();
				return this.applications.projectForIssuance(this.userId, 1, client);
			})).isInstanceOf(org.springframework.dao.DataAccessException.class).rootCause()
					.isInstanceOfSatisfying(org.postgresql.util.PSQLException.class, ex -> {
						assertThat(ex.getSQLState()).isEqualTo("42501");
						assertThat(ex.getMessage()).contains("iam_user_role");
					});
			assertThat(snapshot()).isEqualTo(before);
		}
		finally { this.jdbc.sql("DROP OWNED BY " + role).update(); this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	@ParameterizedTest
	@ValueSource(strings = { "assignment", "role", "disable", "credential" })
	void waitingForCommittedMutationsRechecksCurrentAssignmentsAndSubjectState(String mutation) throws Exception {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var client = client(this.resourceId, Set.of(this.roleId));
		var changed = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					switch (mutation) {
						case "assignment" -> this.bindings.change(this.userId, this.roleId, 1, false, AUDIT);
						case "role" -> this.roles.setEnabled(this.roleId, 1, false, AUDIT);
						case "disable" -> this.states.disable(this.userId, AUDIT);
						default -> { this.users.lockById(this.userId); this.users.invalidateAuthentications(this.userId, 1); }
					}
					changed.countDown(); awaitLatch(release);
				}));
				awaitLatch(changed);
				var issuer = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-application-waiting-issuer"); return this.applications.projectForIssuance(this.userId, 1, client);
				}));
				awaitLockWait("iam-application-waiting-issuer");
				release.countDown(); writer.get(10, TimeUnit.SECONDS);
				var access = issuer.get(10, TimeUnit.SECONDS);
				if (mutation.equals("disable") || mutation.equals("credential")) { assertThat(access).isEmpty(); }
				else { assertThat(access.orElseThrow().roles()).isEmpty(); }
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void parallelIssuersShareTheSubjectLockAndAnAssignmentChangeWaitsForCommit() throws Exception {
		this.bindings.change(this.userId, this.roleId, 0, true, AUDIT);
		var client = client(this.resourceId, Set.of(this.roleId));
		var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
			try {
				var issuer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
					assertThat(this.applications.projectForIssuance(this.userId, 1, client).orElseThrow().roles()).hasSize(1);
					locked.countDown(); awaitLatch(release);
				}));
				awaitLatch(locked);
				var parallel = executor.submit(() -> project(this.userId, 1, client));
				assertThat(parallel.get(10, TimeUnit.SECONDS).orElseThrow().roles()).hasSize(1);
				var administrator = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
					applicationName("iam-application-waiting-admin"); return this.bindings.change(this.userId, this.roleId, 1, false, AUDIT);
				}));
				awaitLockWait("iam-application-waiting-admin");
				release.countDown(); issuer.get(10, TimeUnit.SECONDS);
				assertThat(administrator.get(10, TimeUnit.SECONDS).changed()).isTrue();
				assertThat(project(this.userId, 1, client).orElseThrow().roles()).isEmpty();
			}
			finally { release.countDown(); }
		}
	}

	private UUID activeUser(String name) {
		var user = this.users.create(name, name, AUDIT);
		var proof = this.setups.issue(user.id(), AUDIT);
		this.setups.complete(user.id(), proof.token(), PASSWORD, "internal:application-roles", UUID.randomUUID());
		return user.id();
	}
	private IdentityProtocolClients.Snapshot client(UUID resource, Set<UUID> allowed) {
		var config = new IdentityClientConfiguration("Application", resource, List.of("https://app.example/cb"), Set.of("openid", "profile"), allowed);
		return this.protocol.findActiveById(this.clients.create(config, AUDIT).client().id().toString()).orElseThrow();
	}
	private Optional<IdentityApplicationAccess> project(UUID subject, long version, IdentityProtocolClients.Snapshot client) {
		return new TransactionTemplate(this.transactions).execute(tx -> this.applications.projectForIssuance(subject, version, client));
	}
	private List<String> snapshot() {
		return List.of("iam_user", "iam_password", "iam_user_role", "iam_user_resource_role_revision", "iam_resource", "iam_resource_role", "iam_client", "iam_security_audit").stream()
				.map(table -> table + this.jdbc.sql("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM " + table + " t").query(String.class).single()).toList();
	}
	private void applicationName(String value) { this.jdbc.sql("SELECT set_config('application_name',:name,true)").param("name", value).query(String.class).single(); }
	private void awaitLockWait(String name) {
		await().atMost(Duration.ofSeconds(10)).until(() -> this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=:name AND wait_event_type='Lock')")
				.param("name", name).query(Boolean.class).single());
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Concurrent workflow did not reach its checkpoint"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-application-roles-signing-", ".key");
			byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); Files.write(path, bytes);
			java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
