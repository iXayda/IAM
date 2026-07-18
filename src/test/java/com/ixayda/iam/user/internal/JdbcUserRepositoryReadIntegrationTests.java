package com.ixayda.iam.user.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserDirectoryQuery;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserPage;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

class JdbcUserRepositoryReadIntegrationTests extends ApplicationIntegrationTest {

	private static final TenantId SECOND_TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0ce1"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final Instant UPDATED_AT = CREATED_AT.plusSeconds(30);

	private final List<UserReference> usersToDelete = new ArrayList<>();

	@Autowired
	private JdbcUserRepository repository;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createSecondTenant() {
		this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES (:tenantId, 'second-user-tenant', 'Second User Tenant')
				""").param("tenantId", SECOND_TENANT_ID.value()).update();
	}

	@AfterEach
	void deleteFixtures() {
		this.usersToDelete.forEach(reference -> {
			this.jdbcClient.sql("""
					DELETE FROM user_login_identifiers
					WHERE tenant_id = :tenantId AND user_id = :userId
					""")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", SECOND_TENANT_ID.value())
			.update();
	}

	@Test
	void findsAUserAndAllIdentifiersByIdOrLoginKey() {
		LoginIdentifier email = LoginIdentifier.email("O'Reilly;--@Example.COM");
		User user = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(email, LoginIdentifier.phone("+1 (555) 123-4567"), LoginIdentifier.username("alice")));
		insert(user);

		assertThat(this.repository.findById(TenantId.DEFAULT, user.id())).contains(user);
		assertThat(this.repository.findByLogin(TenantId.DEFAULT, LoginKey.from(email.value()))).contains(user);
		assertThat(this.repository.findByLogin(TenantId.DEFAULT, LoginKey.from("alice"))).contains(user);
	}

	@Test
	void scopesTypeIndependentLoginKeysToATenant() {
		User usernameUser = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("15551234567")));
		User phoneUser = user(SECOND_TENANT_ID, UserStatus.ACTIVE,
				List.of(LoginIdentifier.phone("+1 (555) 123-4567")));
		insert(usernameUser);
		insert(phoneUser);
		LoginKey phoneKey = LoginKey.from("+1 (555) 123-4567");

		assertThat(this.repository.findByLogin(TenantId.DEFAULT, phoneKey)).contains(usernameUser);
		assertThat(this.repository.findByLogin(SECOND_TENANT_ID, phoneKey)).contains(phoneUser);
		assertThat(this.repository.findById(SECOND_TENANT_ID, usernameUser.id())).isEmpty();
		assertThat(this.repository.findById(TenantId.DEFAULT, phoneUser.id())).isEmpty();
		TenantId unknownTenantId = TenantId.random();
		assertThat(this.repository.findById(unknownTenantId, usernameUser.id())).isEmpty();
		assertThat(this.repository.findByLogin(unknownTenantId, phoneKey)).isEmpty();
	}

	@Test
	void returnsDeletedUsersWithoutReleasingTheirIdentifiers() {
		User deleted = new User(UserId.random(), TenantId.DEFAULT,
				List.of(LoginIdentifier.email("deleted@example.com")), UserStatus.DELETED, 3, CREATED_AT, UPDATED_AT, null);
		insert(deleted);

		assertThat(this.repository.findById(TenantId.DEFAULT, deleted.id())).contains(deleted);
		assertThat(this.repository.findByLogin(TenantId.DEFAULT, LoginKey.from("deleted@example.com")))
			.contains(deleted);
	}

	@Test
	void pagesCompleteVisibleUsersBeforeJoiningTheirIdentifiers() {
		User active = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("page-active"), LoginIdentifier.email("page-active@example.com"),
						LoginIdentifier.phone("+1 555 000 0001")));
		User disabled = user(TenantId.DEFAULT, UserStatus.DISABLED,
				List.of(LoginIdentifier.username("page-disabled"), LoginIdentifier.email("page-disabled@example.com")));
		User locked = user(TenantId.DEFAULT, UserStatus.LOCKED,
				List.of(LoginIdentifier.username("page-locked")));
		User deleted = user(TenantId.DEFAULT, UserStatus.DELETED,
				List.of(LoginIdentifier.username("page-deleted")));
		User otherTenant = user(SECOND_TENANT_ID, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("page-other")));
		List.of(active, disabled, locked, deleted, otherTenant).forEach(this::insert);
		List<User> visible = List.of(active, disabled, locked).stream()
			.sorted(java.util.Comparator.comparing((user) -> user.id().toString()))
			.toList();

		UserPage first = this.repository.findDirectoryPage(TenantId.DEFAULT, UserDirectoryQuery.all(0, 2));
		UserPage second = this.repository.findDirectoryPage(TenantId.DEFAULT, UserDirectoryQuery.all(2, 2));

		assertThat(first.totalResults()).isEqualTo(3);
		assertThat(first.users()).containsExactlyElementsOf(visible.subList(0, 2));
		assertThat(second.totalResults()).isEqualTo(3);
		assertThat(second.users()).containsExactlyElementsOf(visible.subList(2, 3));
		assertThat(first.users()).allSatisfy((user) -> assertThat(user.identifiers()).isNotEmpty());
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT, UserDirectoryQuery.all(3, 2)).users())
			.isEmpty();
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT, UserDirectoryQuery.all(0, 0)))
			.extracting(UserPage::totalResults, UserPage::users)
			.containsExactly(3L, List.of());
	}

	@Test
	void filtersByCanonicalIdAndMappedPrimaryUserName() {
		User usernameFirst = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("primary-user"), LoginIdentifier.email("secondary@example.com")));
		User emailOnly = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.email("Target@Example.com")));
		User phoneOnly = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.phone("+1 555 000 0002")));
		insert(usernameFirst);
		insert(emailOnly);
		insert(phoneOnly);

		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT,
				UserDirectoryQuery.primaryIdentifierEquals(0, 10, "PRIMARY-USER")).users())
			.containsExactly(usernameFirst);
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT,
				UserDirectoryQuery.primaryIdentifierEquals(0, 10, "target@example.COM")).users())
			.containsExactly(emailOnly);
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT,
				UserDirectoryQuery.primaryIdentifierEquals(0, 10, "secondary@example.com")).users())
			.isEmpty();
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT,
				UserDirectoryQuery.primaryIdentifierEquals(0, 10, "+1 555 000 0002")).users())
			.containsExactly(phoneOnly);
		assertThat(this.repository.findDirectoryPage(TenantId.DEFAULT,
				UserDirectoryQuery.idEquals(0, 10, emailOnly.id())).users())
			.containsExactly(emailOnly);
		assertThat(this.repository.findDirectoryPage(SECOND_TENANT_ID,
				UserDirectoryQuery.idEquals(0, 10, emailOnly.id())).users())
			.isEmpty();
	}

	@Test
	void exposesTheDirectoryPagingIndex() {
		List<String> definitions = this.jdbcClient.sql("""
				SELECT indexdef
				FROM pg_indexes
				WHERE schemaname = current_schema()
				  AND indexname IN (
				      'users_tenant_directory_page_idx',
				      'user_login_identifiers_tenant_phone_value_idx'
				  )
				ORDER BY indexname
				""").query(String.class).list();

		assertThat(definitions).hasSize(2)
			.anySatisfy((definition) -> assertThat(definition)
				.contains("(tenant_id, user_id)", "WHERE (status <> 'deleted'::text)"))
			.anySatisfy((definition) -> assertThat(definition)
				.contains("(tenant_id, identifier_value, user_id)", "WHERE (identifier_type = 'phone'::text)"));
	}

	@Test
	void reportsAStoredUserWithoutLoginIdentifiersAsInvalid() {
		UserId userId = UserId.random();
		this.usersToDelete.add(new UserReference(TenantId.DEFAULT, userId));
		this.jdbcClient.sql("""
				INSERT INTO users (user_id, tenant_id, created_at, updated_at)
				VALUES (:userId, :tenantId, :createdAt, :updatedAt)
				""")
			.param("userId", userId.value())
			.param("tenantId", TenantId.DEFAULT.value())
			.param("createdAt", databaseValue(CREATED_AT))
			.param("updatedAt", databaseValue(UPDATED_AT))
			.update();

		assertThatThrownBy(() -> this.repository.findById(TenantId.DEFAULT, userId))
			.isInstanceOf(IllegalStateException.class)
			.hasMessage("User has no login identifiers: " + userId);
	}

	@Test
	void requiresAReadWriteTransactionForTheSharedUserLock() {
		User user = user(TenantId.DEFAULT, UserStatus.ACTIVE, List.of(LoginIdentifier.username("locked-user")));
		insert(user);

		assertThatThrownBy(() -> this.repository.findByIdForShare(TenantId.DEFAULT, user.id()))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = new TransactionTemplate(this.transactionManager);
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly
			.execute(status -> this.repository.findByIdForShare(TenantId.DEFAULT, user.id())))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User write requires an existing read-write transaction");

		TransactionTemplate readWrite = new TransactionTemplate(this.transactionManager);
		Optional<User> locked = readWrite
			.execute(status -> this.repository.findByIdForShare(TenantId.DEFAULT, user.id()));
		assertThat(locked).contains(user);
	}

	@Test
	void requiresAReadWriteTransactionForTheExclusiveUserLock() {
		User user = user(TenantId.DEFAULT, UserStatus.ACTIVE,
				List.of(LoginIdentifier.username("exclusively-locked-user")));
		insert(user);

		assertThatThrownBy(() -> this.repository.findByIdForUpdate(TenantId.DEFAULT, user.id()))
			.isInstanceOf(IllegalTransactionStateException.class);

		TransactionTemplate readOnly = new TransactionTemplate(this.transactionManager);
		readOnly.setReadOnly(true);
		assertThatThrownBy(() -> readOnly
			.execute(status -> this.repository.findByIdForUpdate(TenantId.DEFAULT, user.id())))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("User write requires an existing read-write transaction");

		TransactionTemplate readWrite = new TransactionTemplate(this.transactionManager);
		Optional<User> locked = readWrite
			.execute(status -> this.repository.findByIdForUpdate(TenantId.DEFAULT, user.id()));
		assertThat(locked).contains(user);
	}

	private User user(TenantId tenantId, UserStatus status, List<LoginIdentifier> identifiers) {
		return new User(UserId.random(), tenantId, identifiers, status, 3, CREATED_AT, UPDATED_AT,
				CREATED_AT.plusSeconds(15));
	}

	private void insert(User user) {
		this.usersToDelete.add(new UserReference(user.tenantId(), user.id()));
		this.jdbcClient.sql("""
				INSERT INTO users
				    (user_id, tenant_id, status, version, security_version,
				     created_at, updated_at, last_login_at)
				VALUES
				    (:userId, :tenantId, :status, :version, :securityVersion, :createdAt, :updatedAt,
				     CAST(:lastLoginAt AS timestamptz))
				""")
			.param("userId", user.id().value())
			.param("tenantId", user.tenantId().value())
			.param("status", user.status().name().toLowerCase(Locale.ROOT))
			.param("version", user.version())
			.param("securityVersion", user.securityVersion())
			.param("createdAt", databaseValue(user.createdAt()))
			.param("updatedAt", databaseValue(user.updatedAt()))
			.param("lastLoginAt", databaseValue(user.lastLoginAt()))
			.update();
		user.identifiers().forEach(identifier -> this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value, created_at, updated_at)
				VALUES
				    (:tenantId, :userId, :type, :value, :canonicalValue, :createdAt, :updatedAt)
				""")
			.param("tenantId", user.tenantId().value())
			.param("userId", user.id().value())
			.param("type", identifier.type().name().toLowerCase(Locale.ROOT))
			.param("value", identifier.value())
			.param("canonicalValue", identifier.canonicalValue())
			.param("createdAt", databaseValue(user.createdAt()))
			.param("updatedAt", databaseValue(user.updatedAt()))
			.update());
	}

	private static OffsetDateTime databaseValue(Instant instant) {
		return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
