package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEntry;
import com.ixayda.iam.model.SecurityAuditEntry.Outcome;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditPage;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class SecurityAuditSearchIntegrationTests {

	private static final Instant RECORDED = Instant.parse("2026-10-01T08:12:35.123456Z");
	private static final UUID TARGET = new UUID(1, 1);
	private static final UUID CORRELATION = new UUID(2, 1);
	private static final SecurityAuditFilter ALL = filter(null, null, null, null, null, null, null, null);
	private static final List<String> TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit");

	@Autowired
	private SecurityAudits audits;
	@Autowired
	private IdentityUsers users;
	@Autowired
	private JdbcClient jdbc;
	@Autowired
	private PlatformTransactionManager transactions;
	@Autowired
	private PostgreSQLContainer postgres;

	@BeforeEach
	void clean() {
		for (String table : List.of("iam_browser_session_attributes", "iam_browser_session", "iam_password_authentication_limit",
				"iam_security_audit", "iam_password_recovery", "iam_user_setup", "iam_password", "iam_user")) {
			this.jdbc.sql("DELETE FROM " + table).update();
		}
	}

	@Test
	void emptyQueryAndNoMatchesHaveNoContinuation() {
		assertThat(this.audits.search(ALL, 20, null)).isEqualTo(new SecurityAuditPage(List.of(), null));
		seed(1, Action.USER_CREATED);
		assertThat(this.audits.search(filter(null, null, null, null, "missing", null, null, null), 20, null))
				.isEqualTo(new SecurityAuditPage(List.of(), null));
	}

	@ParameterizedTest
	@EnumSource(Action.class)
	void readsEveryExistingActionAndItsStoredAttributionWithoutInventingATarget(Action action) {
		UUID target = action.requiresTarget() ? TARGET : null;
		var expected = seed(id(1), action, target, "system:reader", "internal:test", CORRELATION, RECORDED);
		var page = this.audits.search(ALL, 1, null);
		assertThat(page.items()).containsExactly(expected);
		assertThat(page.nextCursor()).isNull();
	}

	@ParameterizedTest
	@MethodSource("filters")
	void filtersAreOptionalExactAndCombinedWithAnd(SecurityAuditFilter filter, List<Integer> expected) {
		seed(id(1), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, RECORDED);
		seed(id(2), Action.PASSWORD_AUTH_FAILED, null, "anonymous", "browser:login", id(22), RECORDED.plusSeconds(1));
		seed(id(3), Action.USER_DISABLED, TARGET, "system:reader-extra", "internal:test-extra", CORRELATION, RECORDED.plusSeconds(2));
		seed(id(4), Action.USER_CREATED, id(44), "System:reader", "Internal:test", id(24), RECORDED.plusSeconds(3));
		assertThat(this.audits.search(filter, 100, null).items()).extracting(SecurityAuditEntry::id)
				.containsExactlyElementsOf(expected.stream().map(SecurityAuditSearchIntegrationTests::id).toList());
	}

	static Stream<Arguments> filters() {
		return Stream.of(
				Arguments.of(ALL, List.of(4, 3, 2, 1)),
				Arguments.of(filter(null, null, Action.USER_CREATED, null, null, null, null, null), List.of(4, 1)),
				Arguments.of(filter(null, null, null, Outcome.SUCCESS, null, null, null, null), List.of(4, 3, 1)),
				Arguments.of(filter(null, null, null, Outcome.FAILURE, null, null, null, null), List.of(2)),
				Arguments.of(filter(null, null, null, null, "system:reader", null, null, null), List.of(1)),
				Arguments.of(filter(null, null, null, null, null, "internal:test", null, null), List.of(1)),
				Arguments.of(filter(null, null, null, null, "System:reader", null, null, null), List.of(4)),
				Arguments.of(filter(null, null, null, null, null, "Internal:test", null, null), List.of(4)),
				Arguments.of(filter(null, null, null, null, null, null, TARGET, null), List.of(3, 1)),
				Arguments.of(filter(null, null, null, null, null, null, null, CORRELATION), List.of(3, 1)),
				Arguments.of(filter(RECORDED.plusSeconds(1), null, null, null, null, null, null, null), List.of(4, 3, 2)),
				Arguments.of(filter(null, RECORDED.plusSeconds(2), null, null, null, null, null, null), List.of(2, 1)),
				Arguments.of(filter(RECORDED, RECORDED.plusSeconds(1), Action.USER_CREATED, Outcome.SUCCESS,
						"system:reader", "internal:test", TARGET, CORRELATION), List.of(1)),
				Arguments.of(filter(null, null, Action.USER_CREATED, Outcome.FAILURE, null, null, null, null), List.of()),
				Arguments.of(filter(null, null, null, null, "reader", null, null, null), List.of()),
				Arguments.of(filter(null, null, null, null, null, null, id(999), null), List.of()),
				Arguments.of(filter(null, null, null, null, null, null, null, id(999)), List.of()));
	}

	@Test
	void acceptsMaximumLengthIdentifiersWithoutTrimmingOrChangingCase() {
		String actor = "a".repeat(128);
		String source = "s".repeat(64);
		seed(id(1), Action.USER_CREATED, TARGET, actor, source, CORRELATION, RECORDED);
		assertThat(this.audits.search(filter(null, null, null, null, actor, source, null, null), 1, null).items())
				.extracting(SecurityAuditEntry::id).containsExactly(id(1));
	}

	@ParameterizedTest
	@ValueSource(strings = { "2026-10-01T08:12:35.123456Z", "1969-12-31T23:59:59.123456Z" })
	void preservesHalfOpenBoundariesEvenWhenFiltersHaveNanosecondPrecision(String timestamp) {
		Instant base = Instant.parse(timestamp);
		for (int i = 0; i < 3; i++) {
			seed(id(i + 1), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, base.plusNanos(i * 1_000L));
		}
		assertIds(filter(base, base.plusNanos(1_000), null, null, null, null, null, null), 1);
		assertIds(filter(base.plusNanos(1), base.plusNanos(1_001), null, null, null, null, null, null), 2);
		assertIds(filter(base.plusNanos(999), base.plusNanos(1_999), null, null, null, null, null, null), 2);
		assertIds(filter(base.plusNanos(1), base.plusNanos(999), null, null, null, null, null, null), new int[0]);
	}

	@ParameterizedTest
	@ValueSource(ints = { 1, 2, 3, 4, 6 })
	void paginatesIdenticalTimesUsingDatabaseUuidOrderAndKeepsMicroseconds(int size) {
		List<UUID> expected = List.of(id(6), id(5), UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"),
				UUID.fromString("80000000-0000-0000-0000-000000000000"),
				UUID.fromString("7fffffff-ffff-ffff-ffff-ffffffffffff"), id(1));
		for (int i = 0; i < expected.size(); i++) {
			Instant time = i < 2 ? RECORDED.plusNanos((2 - i) * 1_000L) : RECORDED;
			seed(expected.get(i), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, time);
		}
		var found = new ArrayList<UUID>();
		SecurityAuditPage.Cursor cursor = null;
		do {
			var page = this.audits.search(ALL, size, cursor);
			assertThat(page.items()).isNotEmpty().hasSizeLessThanOrEqualTo(size);
			found.addAll(page.items().stream().map(SecurityAuditEntry::id).toList());
			cursor = page.nextCursor();
			if (cursor != null) {
				assertThat(cursor.recordedAt()).isEqualTo(page.items().getLast().recordedAt());
			}
			assertThat(found).hasSizeLessThanOrEqualTo(expected.size());
		} while (cursor != null);
		assertThat(found).containsExactlyElementsOf(expected);
	}

	@Test
	void keepsTheLookaheadAndCanChangePageSizeWithoutAnEmptyExtraPage() {
		for (int i = 1; i <= 102; i++) { seed(i, Action.USER_CREATED); }
		var first = this.audits.search(ALL, 100, null);
		assertThat(first.items()).hasSize(100);
		assertThat(first.items().getLast().id()).isEqualTo(id(3));
		var second = this.audits.search(ALL, 2, first.nextCursor());
		assertThat(second.items()).extracting(SecurityAuditEntry::id).containsExactly(id(2), id(1));
		assertThat(second.nextCursor()).isNull();
		assertThatThrownBy(() -> first.items().clear()).isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	void appliesAllCriteriaBeforeThePageLimitAndOnEveryContinuation() {
		for (int i = 1; i <= 8; i++) {
			seed(id(i), i % 2 == 0 ? Action.USER_CREATED : Action.USER_DISABLED, TARGET,
					"system:reader", "internal:test", CORRELATION, RECORDED.plusSeconds(i));
		}
		var criteria = filter(RECORDED.plusSeconds(2), RECORDED.plusSeconds(8), Action.USER_CREATED,
				Outcome.SUCCESS, "system:reader", "internal:test", TARGET, CORRELATION);
		var first = this.audits.search(criteria, 1, null);
		assertThat(first.items()).extracting(SecurityAuditEntry::id).containsExactly(id(6));
		var second = this.audits.search(criteria, 1, first.nextCursor());
		assertThat(second.items()).extracting(SecurityAuditEntry::id).containsExactly(id(4));
		var third = this.audits.search(criteria, 1, second.nextCursor());
		assertThat(third.items()).extracting(SecurityAuditEntry::id).containsExactly(id(2));
		assertThat(third.nextCursor()).isNull();
	}

	@ParameterizedTest
	@MethodSource("changedFilters")
	void rejectsReusingACursorWithAnyChangedCriterion(SecurityAuditFilter changed) {
		seed(1, Action.USER_CREATED);
		seed(2, Action.USER_CREATED);
		var first = this.audits.search(ALL, 1, null);
		assertThatIllegalArgumentException().isThrownBy(() -> this.audits.search(changed, 1, first.nextCursor()))
				.withMessage("Cursor audit filters do not match");
	}

	static Stream<SecurityAuditFilter> changedFilters() {
		return Stream.of(filter(RECORDED, null, null, null, null, null, null, null),
				filter(null, RECORDED.plusSeconds(1), null, null, null, null, null, null),
				filter(null, null, Action.USER_CREATED, null, null, null, null, null),
				filter(null, null, null, Outcome.SUCCESS, null, null, null, null),
				filter(null, null, null, null, "system:reader", null, null, null),
				filter(null, null, null, null, null, "internal:test", null, null),
				filter(null, null, null, null, null, null, TARGET, null),
				filter(null, null, null, null, null, null, null, CORRELATION));
	}

	@Test
	void cursorWithAnEqualFilterWorksAndAnExhaustedPositionHasNoContinuation() {
		for (int i = 1; i <= 3; i++) { seed(i, Action.USER_CREATED); }
		var equivalent = filter(null, null, null, null, null, null, null, null);
		var first = this.audits.search(ALL, 1, null);
		assertThat(this.audits.search(equivalent, 100, first.nextCursor()).items())
				.extracting(SecurityAuditEntry::id).containsExactly(id(2), id(1));
		assertThat(this.audits.search(ALL, 100, new SecurityAuditPage.Cursor(RECORDED, id(1), ALL)))
				.isEqualTo(new SecurityAuditPage(List.of(), null));
	}

	@ParameterizedTest
	@ValueSource(ints = { Integer.MIN_VALUE, -1, 0, 101, Integer.MAX_VALUE })
	void rejectsUnboundedPages(int size) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.audits.search(ALL, size, null));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", " ", " system:reader", "system:reader ", "system:reader\n", "a\u0000", "用户", "a%", "a' OR 1=1 --", "a\\" })
	void rejectsInvalidActorAndSourceCriteria(String identifier) {
		assertThatIllegalArgumentException().isThrownBy(() -> filter(null, null, null, null, identifier, null, null, null));
		assertThatIllegalArgumentException().isThrownBy(() -> filter(null, null, null, null, null, identifier, null, null));
	}

	@Test
	void rejectsMissingFilterAndInvalidIntervalsOrCursorPositions() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.audits.search(null, 20, null));
		assertThatIllegalArgumentException().isThrownBy(() -> filter(null, null, null, null, "a".repeat(129), null, null, null));
		assertThatIllegalArgumentException().isThrownBy(() -> filter(null, null, null, null, null, "s".repeat(65), null, null));
		assertThatIllegalArgumentException().isThrownBy(() -> filter(RECORDED, RECORDED, null, null, null, null, null, null));
		assertThatIllegalArgumentException().isThrownBy(() -> filter(RECORDED, RECORDED.minusNanos(1), null, null, null, null, null, null));
		for (Instant time : List.of(Instant.MIN, Instant.MAX, Instant.parse("-4712-01-01T00:00:00Z").minusNanos(1),
				Instant.parse("+294277-01-01T00:00:00Z"))) {
			assertThatIllegalArgumentException().isThrownBy(() -> filter(time, null, null, null, null, null, null, null));
			assertThatIllegalArgumentException().isThrownBy(() -> filter(null, time, null, null, null, null, null, null));
			assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditPage.Cursor(time, id(1), ALL));
		}
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditPage.Cursor(RECORDED.plusNanos(1), id(1), ALL));
		assertThatNullPointerException().isThrownBy(() -> new SecurityAuditPage.Cursor(null, id(1), ALL));
		assertThatNullPointerException().isThrownBy(() -> new SecurityAuditPage.Cursor(RECORDED, null, ALL));
		assertThatNullPointerException().isThrownBy(() -> new SecurityAuditPage.Cursor(RECORDED, id(1), null));
	}

	@Test
	void acceptsFiniteTimesAtTheSupportedRangeBoundaries() {
		Instant earliest = Instant.parse("-4712-01-01T00:00:00Z");
		Instant latest = Instant.parse("+294276-12-31T23:59:59.999999Z");
		seed(id(1), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, earliest);
		seed(id(2), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, latest);
		assertIds(filter(earliest, null, null, null, null, null, null, null), 2, 1);
		assertIds(filter(null, latest, null, null, null, null, null, null), 1);
	}

	@Test
	void laterPagesKeepTheirPositionButAreNotAFixedSnapshot() {
		for (int i = 1; i <= 4; i++) { seed(i, Action.USER_CREATED); }
		var first = this.audits.search(ALL, 2, null);
		seed(id(9), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, RECORDED.plusSeconds(1));
		seed(id(10), Action.USER_CREATED, TARGET, "system:reader", "internal:test", CORRELATION, RECORDED.minusSeconds(1));
		assertThat(this.audits.search(ALL, 100, first.nextCursor()).items()).extracting(SecurityAuditEntry::id)
				.containsExactly(id(2), id(1), id(10));
		assertIds(ALL, 9, 4, 3, 2, 1, 10);
	}

	@Test
	void doesNotReadUncommittedEventsAndCanSeeALaterCommitOnTheNextPage() throws Exception {
		seed(3, Action.USER_CREATED);
		seed(2, Action.USER_CREATED);
		var inserted = new CountDownLatch(1);
		var commit = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				seed(1, Action.USER_CREATED);
				inserted.countDown();
				try { assertThat(commit.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			SecurityAuditPage first;
			try {
				assertThat(inserted.await(10, TimeUnit.SECONDS)).isTrue();
				assertIds(ALL, 3, 2);
				first = this.audits.search(ALL, 1, null);
			}
			finally { commit.countDown(); }
			writer.get(10, TimeUnit.SECONDS);
			assertThat(this.audits.search(ALL, 100, first.nextCursor()).items()).extracting(SecurityAuditEntry::id)
					.containsExactly(id(2), id(1));
		}
	}

	@Test
	void queriesOnlyAuditColumnsWithAReadOnlyRoleWithoutChangingAnyBusinessOrAuditData() {
		var context = new SecurityAuditContext("system:reader", "internal:test", CORRELATION);
		var user = this.users.create("alice", "Private Name", context);
		this.users.setInitialPassword(user.id(), "Seven amber lanterns beside the river", context);
		var before = snapshot(this.jdbc);
		String role = "audit_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT (id, actor, source, correlation_id, target_user_id, action, outcome, recorded_at) ON iam_security_audit TO " + role).update();
			var read = new TransactionTemplate(this.transactions);
			read.setReadOnly(true);
			read.executeWithoutResult(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + role).update();
				var page = this.audits.search(filter(null, null, null, Outcome.SUCCESS, context.actor(), context.source(), user.id(), CORRELATION), 20, null);
				assertThat(page.items()).extracting(SecurityAuditEntry::action).containsExactly(Action.INITIAL_PASSWORD_SET, Action.USER_CREATED);
				assertThat(page.items().toString()).doesNotContain("Private Name", "Seven amber lanterns", "password_hash");
			});
		}
		finally {
			this.jdbc.sql("DROP OWNED BY " + role).update();
			this.jdbc.sql("DROP ROLE " + role).update();
		}
		assertThat(snapshot(this.jdbc)).isEqualTo(before);
	}

	@Test
	void databaseFailurePropagatesInsteadOfReturningAnEmptySuccess() {
		String role = "audit_denied_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + role).update();
				assertThatThrownBy(() -> this.audits.search(ALL, 20, null)).isInstanceOf(DataAccessException.class);
				tx.setRollbackOnly();
			});
		}
		finally { this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	@Test
	void upgradingV10AddsOnlyQueryIndexesAndPreservesAllExistingData() throws Exception {
		var context = new SecurityAuditContext("system:reader", "internal:test", CORRELATION);
		var user = this.users.create("alice", "Alice", context);
		this.users.setInitialPassword(user.id(), "Seven amber lanterns beside the river", context);
		seed(1, Action.PASSWORD_AUTH_FAILED);
		String schema = "audit_query_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "10").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : TABLES) { previous.sql("INSERT INTO " + table + " SELECT * FROM public." + table).update(); }
				var before = snapshot(previous);
				flyway(schema, "11").migrate();
				assertThat(snapshot(previous)).isEqualTo(before);
				var indexes = previous.sql("SELECT indexdef FROM pg_indexes WHERE schemaname = :schema AND tablename = 'iam_security_audit'")
						.param("schema", schema).query(String.class).list();
				assertThat(indexes).hasSize(5)
						.anySatisfy(index -> assertThat(index).contains("iam_security_audit_recorded_id_idx", "(recorded_at, id)"))
						.anySatisfy(index -> assertThat(index).contains("iam_security_audit_target_recorded_id_idx", "(target_user_id, recorded_at, id)"))
						.anySatisfy(index -> assertThat(index).contains("iam_security_audit_actor_recorded_id_idx", "(actor, recorded_at, id)"))
						.anySatisfy(index -> assertThat(index).contains("iam_security_audit_correlation_recorded_id_idx", "(correlation_id, recorded_at, id)"));
				assertThat(flyway(schema, "11").migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private void assertIds(SecurityAuditFilter filter, int... expected) {
		assertThat(this.audits.search(filter, 100, null).items()).extracting(SecurityAuditEntry::id)
				.containsExactlyElementsOf(java.util.Arrays.stream(expected).mapToObj(SecurityAuditSearchIntegrationTests::id).toList());
	}

	private static UUID id(int number) { return new UUID(0, number); }

	private static SecurityAuditFilter filter(Instant from, Instant until, Action action, Outcome outcome,
			String actor, String source, UUID target, UUID correlation) {
		return new SecurityAuditFilter(from, until, action, outcome, actor, source, target, correlation);
	}

	private void seed(int number, Action action) {
		seed(id(number), action, action.requiresTarget() ? TARGET : null, "system:reader", "internal:test", CORRELATION, RECORDED);
	}

	private SecurityAuditEntry seed(UUID id, Action action, UUID target, String actor, String source, UUID correlation, Instant time) {
		Outcome outcome = action.isFailure() ? Outcome.FAILURE : Outcome.SUCCESS;
		this.jdbc.sql("""
				INSERT INTO iam_security_audit (id, actor, source, correlation_id, target_user_id, action, outcome, recorded_at)
				VALUES (:id, :actor, :source, :correlation, :target, :action, :outcome, :time)
				""").param("id", id).param("actor", actor).param("source", source).param("correlation", correlation)
				.param("target", target).param("action", action.name().toLowerCase(Locale.ROOT))
				.param("outcome", outcome.name().toLowerCase(Locale.ROOT)).param("time", OffsetDateTime.ofInstant(time, ZoneOffset.UTC)).update();
		return new SecurityAuditEntry(id, action, outcome, target, new SecurityAuditContext(actor, source, correlation), time);
	}

	private List<List<String>> snapshot(JdbcClient client) {
		return TABLES.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
