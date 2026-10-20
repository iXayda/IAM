package com.ixayda.iam.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationInteraction;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository.StoredInteraction;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthorizationInteractionsIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final String TABLE = "iam_authorization_interaction";
	@Autowired private IdentityAuthorizationInteractions interactions;
	@Autowired private IdentityAuthorizationInteractionRepository repository;
	@Autowired private AuthorizationSecrets secrets;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private String owner;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.authorization.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() { this.jdbc.sql("TRUNCATE " + TABLE).update(); this.owner = this.interactions.newBrowserOwner(); }

	@AfterEach
	void removeFaults() {
		this.jdbc.sql("ALTER TABLE " + TABLE + " ENABLE TRIGGER USER").update();
		this.jdbc.sql("DROP TRIGGER IF EXISTS interaction_test_fault ON " + TABLE).update();
		this.jdbc.sql("DROP FUNCTION IF EXISTS interaction_test_fault()").update();
		this.jdbc.sql("TRUNCATE " + TABLE).update();
	}

	@Test
	void pendingRequestsAreEncryptedBrowserBoundAndDoNotCreateAnIdentityOrAuthorization() {
		var request = request(); var ticket = this.interactions.create(this.owner, request, 0);
		assertThat(ticket.handle()).matches("[A-Za-z0-9_-]{43}").isNotEqualTo(this.owner);
		assertThat(ticket.interaction().request()).isEqualTo(request);
		assertThat(ticket.interaction().expiresAt()).isEqualTo(ticket.interaction().createdAt().plusSeconds(600));
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
		assertThat(this.interactions.find(this.interactions.newBrowserOwner(), ticket.handle())).isEmpty();
		assertThat(this.interactions.find(this.owner, this.interactions.newBrowserOwner())).isEmpty();
		var row = this.jdbc.sql("SELECT * FROM " + TABLE).query().singleRow();
		assertThat(row.get("request").toString()).startsWith("enc:v1:");
		assertThat(row.toString()).doesNotContain(this.owner, ticket.handle(), request.state(), request.redirectUri(), request.authorizationUri(), "nonce-original", "code_challenge");
		assertThat(ticket.toString() + ticket.interaction() + request).doesNotContain(ticket.handle(), this.owner, request.state(), "nonce-original");
		assertThat(this.jdbc.sql("SELECT count(*) FROM oauth2_authorization").query(Long.class).single()).isZero();
		assertThat(this.jdbc.sql("SELECT count(*) FROM iam_browser_session").query(Long.class).single()).isZero();
	}

	@Test
	void persistedRequestsSurviveApplicationRestartWithoutChangingTheirOwnerOrDeadline() {
		var ticket = this.interactions.create(this.owner, request(), 0);
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(), "spring.datasource.password", this.postgres.getPassword(),
				"iam.authorization.key-file", KEY_FILE.toString(), "spring.main.banner-mode", "off")).run()) {
			assertThat(restarted.getBean(IdentityAuthorizationInteractions.class).find(this.owner, ticket.handle())).contains(ticket.interaction());
			assertThat(restarted.getBean(IdentityAuthorizationInteractions.class).find(this.interactions.newBrowserOwner(), ticket.handle())).isEmpty();
		}
	}

	@Test
	void completionIsSingleUseAndRollsBackWithTheIssuanceTransaction() {
		var ticket = this.interactions.create(this.owner, request(), 0);
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> {
			assertThat(this.interactions.lockForUse(this.owner, ticket.handle())).contains(ticket.interaction());
			this.interactions.complete(this.owner, ticket.handle(), ticket.interaction());
			throw new IllegalStateException("isolated issuance rollback");
		})).isInstanceOf(IllegalStateException.class).hasMessage("isolated issuance rollback");
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
		transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction()));
		assertThat(this.interactions.find(this.owner, ticket.handle())).isEmpty();
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction())))
				.isInstanceOf(IdentityAuthorizationInteractions.ExpiredInteractionException.class);
	}

	@Test
	void concurrentCompletionsAcrossIndependentRequestTransactionsHaveOneWinner() throws Exception {
		var ticket = this.interactions.create(this.owner, request(), 0); var begin = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> completeAfter(begin, ticket)); var second = executor.submit(() -> completeAfter(begin, ticket)); begin.countDown();
			assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.interactions.find(this.owner, ticket.handle())).isEmpty();
	}

	@Test
	void admissionIsBoundedPerBrowserAndCompletedSlotsCanBeReused() {
		var first = this.interactions.create(this.owner, request(), 0);
		for (int i = 1; i < 8; i++) { this.interactions.create(this.owner, request(), 0); }
		assertThatThrownBy(() -> this.interactions.create(this.owner, request(), 0)).isInstanceOf(IdentityAuthorizationInteractions.InteractionLimitException.class);
		assertThat(this.repository.countPending(this.secrets.interactionOwnerDigest(this.owner))).isEqualTo(8);
		assertThatCode(() -> this.interactions.create(this.interactions.newBrowserOwner(), request(), 0)).doesNotThrowAnyException();
		transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, first.handle(), first.interaction()));
		assertThatCode(() -> this.interactions.create(this.owner, request(), 0)).doesNotThrowAnyException();
		assertThat(this.repository.countPending(this.secrets.interactionOwnerDigest(this.owner))).isEqualTo(8);
	}

	@Test
	void concurrentAdmissionsCannotExceedTheBrowserLimit() throws Exception {
		var begin = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(12)) {
			var futures = new ArrayList<java.util.concurrent.Future<Boolean>>();
			for (int i = 0; i < 12; i++) { futures.add(executor.submit(() -> {
				awaitLatch(begin);
				try { this.interactions.create(this.owner, request(), 0); return true; }
				catch (IdentityAuthorizationInteractions.InteractionLimitException ex) { return false; }
			})); }
			begin.countDown();
			int accepted = 0; for (var future : futures) { if (future.get(15, TimeUnit.SECONDS)) { accepted++; } }
			assertThat(accepted).isEqualTo(8);
		}
		assertThat(this.repository.countPending(this.secrets.interactionOwnerDigest(this.owner))).isEqualTo(8);
	}

	@Test
	void invalidExpectedRequestOrBrowserCannotConsumeTheStoredInteraction() {
		var ticket = this.interactions.create(this.owner, request(), 0);
		var changed = new IdentityAuthorizationInteraction(ticket.interaction().id(), request(), 0, ticket.interaction().createdAt(), ticket.interaction().expiresAt());
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), changed)))
				.isInstanceOf(IdentityAuthorizationInteractions.ExpiredInteractionException.class);
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.interactions.newBrowserOwner(), ticket.handle(), ticket.interaction())))
				.isInstanceOf(IdentityAuthorizationInteractions.ExpiredInteractionException.class);
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
	}

	@Test
	void expiredRequestsCannotBeReadLockedOrConsumedAndCleanupIsBounded() {
		var first = expiringInteraction(-1); var second = expiringInteraction(-2); var live = this.interactions.create(this.owner, request(), 0);
		// Admission has already removed the expired records in a bounded cleanup batch.
		assertThat(this.interactions.find(this.owner, first.handle())).isEmpty(); assertThat(this.interactions.find(this.owner, second.handle())).isEmpty();
		transaction().executeWithoutResult(status -> assertThat(this.interactions.lockForUse(this.owner, first.handle())).isEmpty());
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, first.handle(), first.interaction())))
				.isInstanceOf(IdentityAuthorizationInteractions.ExpiredInteractionException.class);
		expiringInteraction(-1); expiringInteraction(-2);
		assertThat(this.interactions.purgeExpired(1)).isEqualTo(1); assertThat(this.interactions.purgeExpired(1)).isEqualTo(1);
		assertThat(this.interactions.purgeExpired(1)).isZero(); assertThat(this.interactions.find(this.owner, live.handle())).contains(live.interaction());
	}

	@Test
	void aDeadlineThatPassesWhileWaitingForTheInteractionLockIsRechecked() throws Exception {
		var ticket = expiringInteraction(2); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> transaction().executeWithoutResult(status -> {
				this.repository.lockByDigest(this.secrets.interactionDigest(ticket.handle()), this.secrets.interactionOwnerDigest(this.owner));
				locked.countDown(); awaitLatch(release);
			}));
			awaitLatch(locked);
			var resumed = executor.submit(() -> transaction().execute(status -> this.interactions.lockForUse(this.owner, ticket.handle())));
			try {
				await().atMost(5, TimeUnit.SECONDS).until(() -> this.jdbc.sql("""
						SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
						    AND query LIKE 'SELECT id FROM iam_authorization_interaction%FOR UPDATE')
						""").query(Boolean.class).single());
				await().atMost(5, TimeUnit.SECONDS).until(() -> !this.repository.now().isBefore(ticket.interaction().expiresAt()));
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS); assertThat(resumed.get(10, TimeUnit.SECONDS)).isEmpty();
		}
	}

	@Test
	void aDeadlineThatPassesDuringCompletionRollsBackTheDeletion() {
		var ticket = expiringInteraction(1);
		fault("BEFORE DELETE", "PERFORM pg_sleep(1.2); RETURN OLD;", false);
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction())))
				.isInstanceOf(IdentityAuthorizationInteractions.ExpiredInteractionException.class);
		assertThat(this.jdbc.sql("SELECT count(*) FROM " + TABLE).query(Long.class).single()).isEqualTo(1);
	}

	@Test
	void cleanupSkipsExpiredRowsOwnedByAnInFlightTransaction() throws Exception {
		var lockedTicket = expiringInteraction(-1); var removable = expiringInteraction(-2); var locked = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var blocker = executor.submit(() -> transaction().executeWithoutResult(status -> {
				this.repository.lockByDigest(this.secrets.interactionDigest(lockedTicket.handle()), this.secrets.interactionOwnerDigest(this.owner));
				locked.countDown(); awaitLatch(release);
			}));
			awaitLatch(locked);
			try {
				assertThat(executor.submit(() -> this.interactions.purgeExpired(10)).get(3, TimeUnit.SECONDS)).isEqualTo(1);
				assertThat(this.jdbc.sql("SELECT id FROM " + TABLE).query(UUID.class).single()).isEqualTo(lockedTicket.interaction().id()).isNotEqualTo(removable.interaction().id());
			}
			finally { release.countDown(); }
			blocker.get(10, TimeUnit.SECONDS);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"id", "handle", "owner", "authentication", "time", "ciphertext", "column"})
	void tamperedMetadataAndExchangedOrAlteredCiphertextsCannotBeUsed(String field) {
		var ticket = this.interactions.create(this.owner, request(), 0); var other = this.interactions.create(this.owner, request(), 0);
		this.jdbc.sql("ALTER TABLE " + TABLE + " DISABLE TRIGGER USER").update();
		String handle = ticket.handle(), owner = this.owner;
		switch (field) {
			case "id" -> this.jdbc.sql("UPDATE " + TABLE + " SET id=:value WHERE id=:id").param("value", UUID.randomUUID()).param("id", ticket.interaction().id()).update();
			case "handle" -> { handle = this.interactions.newBrowserOwner(); this.jdbc.sql("UPDATE " + TABLE + " SET handle_digest=:value WHERE id=:id").param("value", this.secrets.interactionDigest(handle)).param("id", ticket.interaction().id()).update(); }
			case "owner" -> { owner = this.interactions.newBrowserOwner(); this.jdbc.sql("UPDATE " + TABLE + " SET owner_digest=:value WHERE id=:id").param("value", this.secrets.interactionOwnerDigest(owner)).param("id", ticket.interaction().id()).update(); }
			case "authentication" -> this.jdbc.sql("UPDATE " + TABLE + " SET original_authenticated_at=1 WHERE id=:id").param("id", ticket.interaction().id()).update();
			case "time" -> this.jdbc.sql("UPDATE " + TABLE + " SET created_at=created_at-interval '1 second',expires_at=expires_at-interval '1 second' WHERE id=:id").param("id", ticket.interaction().id()).update();
			case "ciphertext" -> this.jdbc.sql("UPDATE " + TABLE + " SET request=request || 'x' WHERE id=:id").param("id", ticket.interaction().id()).update();
			default -> this.jdbc.sql("UPDATE " + TABLE + " SET request=(SELECT request FROM " + TABLE + " WHERE id=:other) WHERE id=:id").param("other", other.interaction().id()).param("id", ticket.interaction().id()).update();
		}
		String lookupOwner = owner, lookupHandle = handle;
		assertThatThrownBy(() -> this.interactions.find(lookupOwner, lookupHandle)).isInstanceOf(IllegalStateException.class)
				.hasMessage("Authorization interaction could not be authenticated or stored").hasNoCause();
	}

	@Test
	void validDatabaseUpdatesAreStillRejectedBecausePendingRequestsAreImmutable() {
		var ticket = this.interactions.create(this.owner, request(), 0);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE " + TABLE + " SET original_authenticated_at=1 WHERE id=:id").param("id", ticket.interaction().id()).update())
				.isInstanceOf(DataIntegrityViolationException.class);
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
	}

	@ParameterizedTest
	@ValueSource(strings = {"suppressed", "reinserted", "deferred"})
	void failedOrSilentlyChangedCompletionCannotPublishConsumption(String failure) {
		var ticket = this.interactions.create(this.owner, request(), 0);
		switch (failure) {
			case "suppressed" -> fault("BEFORE DELETE", "RETURN NULL;", false);
			case "reinserted" -> fault("AFTER DELETE", "INSERT INTO " + TABLE + " VALUES (OLD.*); RETURN OLD;", false);
			default -> fault("AFTER DELETE", "RAISE EXCEPTION 'isolated deferred failure';", true);
		}
		assertThatThrownBy(() -> transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction())))
				.isInstanceOf(RuntimeException.class);
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
	}

	@ParameterizedTest
	@ValueSource(booleans = {false, true})
	void suppressedOrDeferredCreationCannotReturnAnUncommittedHandle(boolean deferred) {
		fault(deferred ? "AFTER INSERT" : "BEFORE INSERT", deferred ? "RAISE EXCEPTION 'isolated deferred failure';" : "RETURN NULL;", deferred);
		assertThatThrownBy(() -> this.interactions.create(this.owner, request(), 0)).isInstanceOf(RuntimeException.class);
		assertThat(this.jdbc.sql("SELECT count(*) FROM " + TABLE).query(Long.class).single()).isZero();
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = {"short", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	void invalidOwnersAndHandlesCannotSupplyBrowserBinding(String invalid) {
		var ticket = this.interactions.create(this.owner, request(), 0);
		assertThat(this.interactions.find(invalid, ticket.handle())).isEmpty(); assertThat(this.interactions.find(this.owner, invalid)).isEmpty();
		assertThatThrownBy(() -> this.interactions.create(invalid, request(), 0)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void completionRequiresTheCallersWritableReadCommittedTransaction() {
		var ticket = this.interactions.create(this.owner, request(), 0);
		assertThatThrownBy(() -> this.interactions.lockForUse(this.owner, ticket.handle())).isInstanceOf(IllegalTransactionStateException.class);
		assertThatThrownBy(() -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction())).isInstanceOf(IllegalTransactionStateException.class);
		var readOnly = transaction(); readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly.executeWithoutResult(status -> this.interactions.lockForUse(this.owner, ticket.handle()))).isInstanceOf(IllegalStateException.class);
		var repeatable = transaction(); repeatable.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
		assertThatThrownBy(() -> repeatable.executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction()))).isInstanceOf(IllegalStateException.class);
		assertThat(this.interactions.find(this.owner, ticket.handle())).contains(ticket.interaction());
	}

	@Test
	void promptNoneUnknownParametersAndInvalidAuthenticationBoundsCannotCreateInteractions() {
		for (var parameter : Map.of("prompt", "none", "unknown", "extension", "max_age", "9223372036854775808", "response_mode", "form_post").entrySet()) {
			var parameters = new HashMap<>(request().parameters()); parameters.put(parameter.getKey(), parameter.getValue());
			assertThatThrownBy(() -> new IdentityAuthorizationInteraction.Request(request().authorizationUri(), request().clientId(), request().redirectUri(), request().state(), request().scopes(), parameters))
					.isInstanceOf(IllegalArgumentException.class);
		}
		assertThatThrownBy(() -> this.interactions.create(this.owner, request(), -1)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.interactions.create(this.owner, request(), Long.MAX_VALUE)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.interactions.purgeExpired(0)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.interactions.purgeExpired(1001)).isInstanceOf(IllegalArgumentException.class);
		assertThat(this.jdbc.sql("SELECT count(*) FROM " + TABLE).query(Long.class).single()).isZero();
	}

	private boolean completeAfter(CountDownLatch begin, IdentityAuthorizationInteractions.Ticket ticket) {
		awaitLatch(begin);
		try { transaction().executeWithoutResult(status -> this.interactions.complete(this.owner, ticket.handle(), ticket.interaction())); return true; }
		catch (IdentityAuthorizationInteractions.ExpiredInteractionException ex) { return false; }
	}
	private IdentityAuthorizationInteractions.Ticket expiringInteraction(int secondsRemaining) {
		var now = this.repository.now().truncatedTo(ChronoUnit.MICROS); var expiry = now.plusSeconds(secondsRemaining);
		var interaction = new IdentityAuthorizationInteraction(UUID.randomUUID(), request(), 0, expiry.minusSeconds(600), expiry);
		String handle = this.interactions.newBrowserOwner();
		transaction().executeWithoutResult(status -> this.repository.insert(new StoredInteraction(interaction, this.secrets.interactionDigest(handle), this.secrets.interactionOwnerDigest(this.owner))));
		return new IdentityAuthorizationInteractions.Ticket(handle, interaction);
	}
	private TransactionTemplate transaction() { var template = new TransactionTemplate(this.transactions); template.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED); return template; }
	private void fault(String timing, String body, boolean deferred) {
		this.jdbc.sql("CREATE FUNCTION interaction_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + body + " END; $$").update();
		this.jdbc.sql("CREATE " + (deferred ? "CONSTRAINT " : "") + "TRIGGER interaction_test_fault " + timing + " ON " + TABLE
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION interaction_test_fault()").update();
	}
	private static IdentityAuthorizationInteraction.Request request() {
		return new IdentityAuthorizationInteraction.Request("https://iam.example/oauth2/authorize", UUID.randomUUID(), "https://orders.example/callback", "state-original",
				Set.of("openid", "profile", "offline_access"), Map.of("code_challenge", "A".repeat(43), "code_challenge_method", "S256", "nonce", "nonce-original", "prompt", "login consent select_account", "max_age", "0", "response_mode", "query"));
	}
	private static void awaitLatch(CountDownLatch latch) {
		try { if (!latch.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Interaction checkpoint was not reached"); } }
		catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new AssertionError(ex); }
	}
	private static Path keyFile() {
		try {
			Path path = Files.createTempFile("iam-interactions-", ".key"); byte[] bytes = new byte[64]; new SecureRandom().nextBytes(bytes);
			Files.write(path, bytes); java.util.Arrays.fill(bytes, (byte) 0); path.toFile().deleteOnExit(); return path;
		}
		catch (java.io.IOException ex) { throw new ExceptionInInitializerError(ex); }
	}

}
