package com.ixayda.iam.service;

import java.sql.DriverManager;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityUserSearchIntegrationTests {

	private static final Instant CREATED = Instant.parse("2026-10-01T08:12:35.123456Z");
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:search-test", "internal:test", UUID.randomUUID());
	private static final List<String> TABLES = List.of("iam_user", "iam_password", "iam_user_setup", "iam_password_recovery",
			"iam_browser_session", "iam_browser_session_attributes", "iam_password_authentication_limit", "iam_security_audit");

	@Autowired
	private IdentityUsers users;
	@Autowired
	private IdentityUserSetups setups;
	@Autowired
	private IdentityUserStates states;
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
	void emptyResultsHaveNoContinuationAndDoNotWriteAnything() {
		assertThat(this.users.search(null, null, 20, null)).isEqualTo(new IdentityUserPage(List.of(), null));
		seed(1, "alice", "Alice", IdentityUser.Status.PENDING);
		var before = snapshot(this.jdbc);
		assertThat(this.users.search("absent", null, 20, null).items()).isEmpty();
		assertThat(this.users.search("absent", null, 20, null).nextCursor()).isNull();
		assertThat(this.users.search(null, IdentityUser.Status.ACTIVE, 20, null).items()).isEmpty();
		assertThat(snapshot(this.jdbc)).isEqualTo(before);
	}

	@ParameterizedTest
	@MethodSource("searchTerms")
	void searchesLiteralSubstringsWithTheDocumentedNormalizationAndCaseRules(String term, List<Integer> expected) {
		seed(1, "alice.example", "Alice Café 用户 😀", IdentityUser.Status.PENDING);
		seed(2, "other-user", "Percent % Under_score ! Back\\slash", IdentityUser.Status.ACTIVE);
		seed(3, "injection", "'; DROP TABLE iam_user; --", IdentityUser.Status.DISABLED);
		seed(4, "alicia", "CAFE", IdentityUser.Status.ACTIVE);
		var page = this.users.search(term, null, 100, null);
		assertThat(page.items()).extracting(IdentityUser::id).containsExactlyElementsOf(expected.stream().map(IdentityUserSearchIntegrationTests::id).toList());
		assertThat(page.nextCursor()).isNull();
	}

	static Stream<Arguments> searchTerms() {
		return Stream.of(Arguments.of(null, List.of(1, 2, 3, 4)), Arguments.of("", List.of(1, 2, 3, 4)),
				Arguments.of("ALI", List.of(1, 4)), Arguments.of("example", List.of(1)), Arguments.of("Cafe\u0301", List.of(1)),
				Arguments.of("café", List.of()), Arguments.of("用户 😀", List.of(1)), Arguments.of("CAF", List.of(4)),
				Arguments.of("%", List.of(2)), Arguments.of("_", List.of(2, 3)), Arguments.of("!", List.of(2)),
				Arguments.of("\\", List.of(2)), Arguments.of("'; DROP TABLE iam_user; --", List.of(3)),
				Arguments.of(" 用户 ", List.of(1)), Arguments.of(" Alice", List.of()));
	}

	@Test
	void combinesStatusWithBothSearchBranchesWithoutReturningOtherStates() {
		seed(1, "target-one", "One", IdentityUser.Status.PENDING);
		seed(2, "target-two", "Two", IdentityUser.Status.DISABLED);
		seed(3, "third", "target", IdentityUser.Status.ACTIVE);
		seed(4, "fourth", "target", IdentityUser.Status.PENDING);
		assertThat(this.users.search("target", IdentityUser.Status.PENDING, 100, null).items())
				.extracting(IdentityUser::id).containsExactly(id(1), id(4));
		assertThat(this.users.search("target", IdentityUser.Status.ACTIVE, 100, null).items())
				.extracting(IdentityUser::id).containsExactly(id(3));
		assertThat(this.users.search(null, IdentityUser.Status.DISABLED, 100, null).items())
				.extracting(IdentityUser::id).containsExactly(id(2));
	}

	@ParameterizedTest
	@ValueSource(ints = { 1, 2, 3, 100 })
	void paginationUsesMicrosecondTimeAndDatabaseUuidOrderingWithoutSkippingOrRepeating(int size) {
		UUID low = UUID.fromString("00000000-0000-0000-0000-000000000001");
		UUID middle = UUID.fromString("7fffffff-ffff-ffff-ffff-ffffffffffff");
		UUID high = UUID.fromString("80000000-0000-0000-0000-000000000000");
		UUID last = UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff");
		seed(last, "last", "Match", IdentityUser.Status.PENDING, CREATED);
		seed(high, "high", "Match", IdentityUser.Status.PENDING, CREATED);
		seed(middle, "middle", "Match", IdentityUser.Status.PENDING, CREATED);
		seed(low, "low", "Match", IdentityUser.Status.PENDING, CREATED);
		seed(id(5), "next-time", "Match", IdentityUser.Status.PENDING, CREATED.plusNanos(1000));
		seed(id(6), "later", "Match", IdentityUser.Status.PENDING, CREATED.plusSeconds(1));
		seed(id(7), "excluded", "Other", IdentityUser.Status.PENDING, CREATED);
		var found = new ArrayList<UUID>();
		IdentityUserPage.Cursor cursor = null;
		do {
			var page = this.users.search("Match", IdentityUser.Status.PENDING, size, cursor);
			assertThat(page.items()).hasSizeLessThanOrEqualTo(size).isNotEmpty();
			found.addAll(page.items().stream().map(IdentityUser::id).toList());
			cursor = page.nextCursor();
			assertThat(found).hasSizeLessThanOrEqualTo(6);
		} while (cursor != null);
		assertThat(found).containsExactly(low, middle, high, last, id(5), id(6));
	}

	@Test
	void oneHundredItemPagesKeepTheLookaheadForTheNextPageAndEndWithoutAnEmptyExtraPage() {
		for (int i = 1; i <= 102; i++) { seed(i, "user-" + i, "User", IdentityUser.Status.PENDING); }
		var first = this.users.search(null, null, 100, null);
		assertThat(first.items()).hasSize(100);
		var second = this.users.search(null, null, 2, first.nextCursor());
		assertThat(second.items()).extracting(IdentityUser::id).containsExactly(id(101), id(102));
		assertThat(second.nextCursor()).isNull();
		assertThatThrownBy(() -> first.items().clear()).isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	void cursorsRequireTheSameNormalizedFiltersButAllowPageSizeChanges() {
		for (int i = 1; i <= 4; i++) { seed(i, "user-" + i, "Café", IdentityUser.Status.PENDING); }
		var first = this.users.search("Cafe\u0301", IdentityUser.Status.PENDING, 1, null);
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.search("other", IdentityUser.Status.PENDING, 1, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.search("Café", null, 1, first.nextCursor()));
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.search("Café", IdentityUser.Status.ACTIVE, 1, first.nextCursor()));
		assertThat(this.users.search("Café", IdentityUser.Status.PENDING, 3, first.nextCursor()).items())
				.extracting(IdentityUser::id).containsExactly(id(2), id(3), id(4));
		var all = this.users.search(null, null, 1, null);
		assertThat(this.users.search("", null, 100, all.nextCursor()).items()).hasSize(3);
	}

	@ParameterizedTest
	@ValueSource(ints = { Integer.MIN_VALUE, -1, 0, 101, Integer.MAX_VALUE })
	void rejectsUnboundedPageSizes(int size) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.search(null, null, size, null));
	}

	@ParameterizedTest
	@MethodSource("invalidTerms")
	void rejectsInvalidUnicodeAndOversizedSearchTerms(String keyword) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.users.search(keyword, null, 20, null))
				.withMessage("Search keyword is invalid");
	}

	static Stream<String> invalidTerms() {
		return Stream.of(" ", "\u00a0\u3000", "bad\u0000", "bad\n", "bad\ud800", "bad\udc00", "😀".repeat(129), "x".repeat(65_537));
	}

	@Test
	void supportsTheMaximumUnicodeTermLength() {
		String name = "😀".repeat(128);
		seed(1, "alice", name, IdentityUser.Status.PENDING);
		assertThat(this.users.search(name, null, 1, null).items()).extracting(IdentityUser::id).containsExactly(id(1));
	}

	@Test
	void laterPagesUseCurrentMembershipAndKeepTheirPositionWhenEarlierRowsAreInserted() {
		for (int i = 1; i <= 4; i++) { seed(i, "user-" + i, "Match", IdentityUser.Status.PENDING); }
		var first = this.users.search("Match", IdentityUser.Status.PENDING, 2, null);
		assertThat(first.items()).extracting(IdentityUser::id).containsExactly(id(1), id(2));
		seed(id(9), "earlier", "Match", IdentityUser.Status.PENDING, CREATED.minusSeconds(1));
		seed(id(10), "later", "Match", IdentityUser.Status.PENDING, CREATED.plusSeconds(1));
		this.states.disable(id(3), SYSTEM);
		var second = this.users.search("Match", IdentityUser.Status.PENDING, 100, first.nextCursor());
		assertThat(second.items()).extracting(IdentityUser::id).containsExactly(id(4), id(10));
		assertThat(second.nextCursor()).isNull();
		assertThat(this.users.search("Match", null, 100, null).items()).extracting(IdentityUser::id)
				.containsExactly(id(9), id(1), id(2), id(3), id(4), id(10));
	}

	@Test
	void readsOnlyCommittedUsersAndSeesALaterCommitOnTheNextPage() throws Exception {
		seed(1, "first", "Match", IdentityUser.Status.PENDING);
		seed(2, "second", "Match", IdentityUser.Status.PENDING);
		var inserted = new CountDownLatch(1);
		var commit = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var writer = executor.submit(() -> new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				seed(3, "third", "Match", IdentityUser.Status.PENDING);
				inserted.countDown();
				try { assertThat(commit.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
			}));
			IdentityUserPage first;
			try {
				assertThat(inserted.await(10, TimeUnit.SECONDS)).isTrue();
				assertThat(this.users.search("Match", null, 100, null).items()).hasSize(2);
				first = this.users.search("Match", null, 1, null);
			}
			finally { commit.countDown(); }
			writer.get(10, TimeUnit.SECONDS);
			assertThat(this.users.search("Match", null, 100, first.nextCursor()).items())
					.extracting(IdentityUser::id).containsExactly(id(2), id(3));
		}
	}

	@Test
	void readsOnlyUserProfileColumnsWithoutCredentialAccessOrWrites() {
		var user = this.users.create("alice", "Alice", SYSTEM);
		var proof = this.setups.issue(user.id(), SYSTEM);
		this.setups.complete(user.id(), proof.token(), "Seven amber lanterns beside the river", "internal:test", UUID.randomUUID());
		var before = snapshot(this.jdbc);
		String role = "search_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT (id, username, display_name, status, created_at) ON iam_user TO " + role).update();
			new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + role).update();
				var page = this.users.search("ALICE", IdentityUser.Status.ACTIVE, 20, null);
				assertThat(page.items()).containsExactly(this.users.findById(user.id()).orElseThrow());
				assertThat(page.nextCursor()).isNull();
			});
		}
		finally {
			this.jdbc.sql("DROP OWNED BY " + role).update();
			this.jdbc.sql("DROP ROLE " + role).update();
		}
		assertThat(snapshot(this.jdbc)).isEqualTo(before);
	}

	@Test
	void databaseFailurePropagatesInsteadOfBecomingAnEmptySuccessfulSearch() {
		String role = "search_denied_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
				this.jdbc.sql("SET LOCAL ROLE " + role).update();
				assertThatThrownBy(() -> this.users.search(null, null, 20, null)).isInstanceOf(DataAccessException.class);
				tx.setRollbackOnly();
			});
		}
		finally { this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	@Test
	void upgradingV9AddsThePagingIndexesWithoutChangingExistingData() throws Exception {
		var user = this.users.create("alice", "Alice", SYSTEM);
		this.users.setInitialPassword(user.id(), "Seven amber lanterns beside the river", SYSTEM);
		String schema = "search_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			flyway(schema, "9").migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema);
				var previous = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				for (String table : TABLES) { copyRows(previous, table); }
				var before = snapshot(previous);
				flyway(schema, "10").migrate();
				assertThat(snapshot(previous)).isEqualTo(before);
				var indexes = previous.sql("SELECT indexdef FROM pg_indexes WHERE schemaname = :schema AND tablename = 'iam_user'")
						.param("schema", schema).query(String.class).list();
				assertThat(indexes).anySatisfy(index -> assertThat(index).contains("iam_user_created_id_idx", "(created_at, id)"))
						.anySatisfy(index -> assertThat(index).contains("iam_user_status_created_id_idx", "(status, created_at, id)"));
				assertThat(flyway(schema, "10").migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private static UUID id(int number) { return new UUID(0, number); }

	private void seed(int number, String username, String displayName, IdentityUser.Status status) {
		seed(id(number), username, displayName, status, CREATED);
	}

	private void seed(UUID id, String username, String displayName, IdentityUser.Status status, Instant created) {
		this.jdbc.sql("INSERT INTO iam_user (id, username, display_name, status, created_at) VALUES (:id, :username, :name, :status, :created)")
				.param("id", id).param("username", username).param("name", displayName).param("status", status.name().toLowerCase(java.util.Locale.ROOT))
				.param("created", OffsetDateTime.ofInstant(created, ZoneOffset.UTC)).update();
	}

	private List<List<String>> snapshot(JdbcClient client) {
		return TABLES.stream().map(table -> client.sql("SELECT row_to_json(t)::text FROM " + table + " t ORDER BY 1").query(String.class).list()).toList();
	}

	private Flyway flyway(String schema, String target) {
		return Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())
				.schemas(schema).defaultSchema(schema).target(target).load();
	}

}
