package com.ixayda.iam.tenant.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantConcurrentUpdateException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantStatus;
import org.junit.jupiter.api.Test;

class DefaultTenantOperationsTests {

	private static final TenantId TENANT_ID =
			new TenantId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc1"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private final JdbcTenantRepository repository = mock(JdbcTenantRepository.class);

	private final TenantTimeSource timeSource = mock(TenantTimeSource.class);

	private final DefaultTenantOperations operations =
			new DefaultTenantOperations(this.repository, this.timeSource);

	@Test
	void usesALockedReadWhenRequiringAnActiveTenantForWrite() {
		Tenant active = tenant(TenantStatus.ACTIVE, 0, CREATED_AT);
		when(this.repository.findByIdForShare(TENANT_ID)).thenReturn(Optional.of(active));

		assertThat(this.operations.requireActiveForWrite(TENANT_ID)).isEqualTo(active);
		verify(this.repository).findByIdForShare(TENANT_ID);
	}

	@Test
	void returnsTheLatestTenantWhenAConcurrentRequestReachedTheTargetStatus() {
		Tenant active = tenant(TenantStatus.ACTIVE, 0, CREATED_AT);
		Tenant disabled = tenant(TenantStatus.DISABLED, 3, CREATED_AT.plusSeconds(3));
		TenantConcurrentUpdateException conflict = new TenantConcurrentUpdateException(TENANT_ID, 0);
		when(this.repository.findById(TENANT_ID)).thenReturn(Optional.of(active)).thenReturn(Optional.of(disabled));
		when(this.repository.updateStatus(any(Tenant.class), any(Tenant.class))).thenThrow(conflict);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThat(this.operations.disable(TENANT_ID)).isEqualTo(disabled);
		verify(this.repository).updateStatus(any(Tenant.class), any(Tenant.class));
		verify(this.repository, times(2)).findById(TENANT_ID);
	}

	@Test
	void preservesTheConflictWhenTheConcurrentRequestDidNotReachTheTargetStatus() {
		Tenant active = tenant(TenantStatus.ACTIVE, 0, CREATED_AT);
		TenantConcurrentUpdateException conflict = new TenantConcurrentUpdateException(TENANT_ID, 0);
		when(this.repository.findById(TENANT_ID)).thenReturn(Optional.of(active));
		when(this.repository.updateStatus(any(Tenant.class), any(Tenant.class))).thenThrow(conflict);
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThatThrownBy(() -> this.operations.disable(TENANT_ID)).isSameAs(conflict);
	}

	@Test
	void preservesAMonotonicTimestampWhenTheClockMovesBackward() {
		Instant storedTime = CREATED_AT.plusSeconds(60);
		Tenant active = tenant(TenantStatus.ACTIVE, 0, storedTime);
		Tenant disabled = tenant(TenantStatus.DISABLED, 1, storedTime);
		when(this.repository.findById(TENANT_ID)).thenReturn(Optional.of(active));
		when(this.repository.updateStatus(active, disabled)).thenReturn(disabled);
		when(this.timeSource.now()).thenReturn(CREATED_AT);

		assertThat(this.operations.disable(TENANT_ID)).isEqualTo(disabled);
		verify(this.repository).updateStatus(active, disabled);
	}

	private Tenant tenant(TenantStatus status, long version, Instant updatedAt) {
		return new Tenant(TENANT_ID, "acme", "Acme", status, version, CREATED_AT, updatedAt);
	}

}
