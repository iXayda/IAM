package com.ixayda.iam.tenant.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantAlreadyExistsException;
import com.ixayda.iam.tenant.TenantConcurrentUpdateException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;

class JdbcTenantRepositoryIntegrationTests extends ApplicationIntegrationTest {

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private JdbcTenantRepository repository;

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
	void storesAndFindsATenant() {
		Tenant tenant = tenant("acme", "Acme");

		assertThat(this.repository.insert(tenant)).isEqualTo(tenant);
		assertThat(this.repository.findById(tenant.id())).contains(tenant);
		assertThat(this.repository.findBySlug(tenant.slug())).contains(tenant);
	}

	@Test
	void rejectsADuplicateSlug() {
		Tenant first = tenant("duplicate", "First");
		Tenant second = tenant("duplicate", "Second");
		this.repository.insert(first);

		assertThatThrownBy(() -> this.repository.insert(second))
			.isInstanceOf(TenantAlreadyExistsException.class)
			.extracting("slug")
			.isEqualTo("duplicate");
	}

	@Test
	void updatesAStatusUsingOptimisticLocking() {
		Tenant current = tenant("concurrent", "Concurrent");
		this.repository.insert(current);
		Tenant disabled = current.disable(current.updatedAt().plusSeconds(1));

		assertThat(this.repository.updateStatus(current, disabled)).isEqualTo(disabled);
		assertThat(this.repository.findById(current.id())).contains(disabled);
		assertThatThrownBy(() -> this.repository.updateStatus(current, disabled))
			.isInstanceOf(TenantConcurrentUpdateException.class)
			.extracting("expectedVersion")
			.isEqualTo(0L);
	}

	private Tenant tenant(String slug, String displayName) {
		Tenant tenant = new Tenant(TenantId.random(), slug, displayName, TenantStatus.ACTIVE, 0, CREATED_AT,
				CREATED_AT);
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

}
