package com.ixayda.iam.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.ApplicationIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class TenantOperationsIntegrationTests extends ApplicationIntegrationTest {

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteCreatedTenants() {
		this.tenantsToDelete.forEach(tenantId -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void createsAndFindsATenant() {
		Tenant created = create("acme", " Acme ");

		assertThat(created.id()).isNotEqualTo(TenantId.DEFAULT);
		assertThat(created.displayName()).isEqualTo("Acme");
		assertThat(created.status()).isEqualTo(TenantStatus.ACTIVE);
		assertThat(created.version()).isZero();
		assertThat(this.tenants.findById(created.id())).contains(created);
		assertThat(this.tenants.findBySlug("acme")).contains(created);
	}

	@Test
	void rejectsDuplicateSlugs() {
		create("duplicate", "First");

		assertThatThrownBy(() -> this.tenants.create(new CreateTenantRequest("duplicate", "Second")))
			.isInstanceOf(TenantAlreadyExistsException.class);
	}

	@Test
	void changesStatusIdempotently() {
		Tenant created = create("lifecycle", "Lifecycle");

		Tenant disabled = this.tenants.disable(created.id());
		assertThat(disabled.status()).isEqualTo(TenantStatus.DISABLED);
		assertThat(disabled.version()).isOne();
		assertThat(this.tenants.disable(created.id())).isEqualTo(disabled);
		assertThatThrownBy(() -> this.tenants.requireActive(created.id()))
			.isInstanceOf(TenantDisabledException.class);

		Tenant active = this.tenants.activate(created.id());
		assertThat(active.status()).isEqualTo(TenantStatus.ACTIVE);
		assertThat(active.version()).isEqualTo(2);
		assertThat(this.tenants.activate(created.id())).isEqualTo(active);
		assertThat(this.tenants.requireActive(created.id())).isEqualTo(active);
	}

	@Test
	void convergesConcurrentDisables() throws Exception {
		Tenant created = create("concurrent-disable", "Concurrent Disable");
		int callers = 8;
		CountDownLatch ready = new CountDownLatch(callers);
		CountDownLatch start = new CountDownLatch(1);
		List<Future<Tenant>> results = new ArrayList<>();

		try (ExecutorService executor = Executors.newFixedThreadPool(callers)) {
			for (int i = 0; i < callers; i++) {
				results.add(executor.submit(() -> {
					ready.countDown();
					start.await();
					return this.tenants.disable(created.id());
				}));
			}
			boolean allReady;
			try {
				allReady = ready.await(5, TimeUnit.SECONDS);
			}
			finally {
				start.countDown();
			}
			assertThat(allReady).isTrue();

			List<Tenant> transitions = new ArrayList<>();
			for (Future<Tenant> result : results) {
				transitions.add(result.get(10, TimeUnit.SECONDS));
			}
			Tenant stored = this.tenants.findById(created.id()).orElseThrow();
			assertThat(transitions).allMatch(stored::equals);
			assertThat(stored.status()).isEqualTo(TenantStatus.DISABLED);
			assertThat(stored.version()).isOne();
		}
	}

	@Test
	void toleratesAStoredTimestampAheadOfTheSystemClock() {
		Tenant created = create("future-timestamp", "Future Timestamp");
		Instant future = created.updatedAt().plusSeconds(3_600);
		this.jdbcClient.sql("UPDATE tenants SET updated_at = :updatedAt WHERE tenant_id = :tenantId")
			.param("updatedAt", OffsetDateTime.ofInstant(future, ZoneOffset.UTC))
			.param("tenantId", created.id().value())
			.update();

		Tenant disabled = this.tenants.disable(created.id());

		assertThat(disabled.status()).isEqualTo(TenantStatus.DISABLED);
		assertThat(disabled.updatedAt()).isEqualTo(future);
	}

	@Test
	void reportsMissingAndProtectedTenants() {
		TenantId missing = TenantId.random();

		assertThatThrownBy(() -> this.tenants.requireActive(missing)).isInstanceOf(TenantNotFoundException.class);
		assertThatThrownBy(() -> this.tenants.disable(TenantId.DEFAULT)).isInstanceOf(ProtectedTenantException.class);
		assertThat(this.tenants.requireActive(TenantId.DEFAULT).isBuiltInDefault()).isTrue();
	}

	private Tenant create(String slug, String displayName) {
		Tenant tenant = this.tenants.create(new CreateTenantRequest(slug, displayName));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

}
