package com.ixayda.iam.organization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class OrganizationMembershipTests {

	private static final OrganizationId ORGANIZATION_ID =
			OrganizationId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d42");

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0d45");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void startsAnActiveMembershipWithItsCompositeIdentity() {
		OrganizationMembership membership = activeMembership();

		assertThat(membership.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(membership.organizationId()).isEqualTo(ORGANIZATION_ID);
		assertThat(membership.userId()).isEqualTo(USER_ID);
		assertThat(membership.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(membership.version()).isZero();
		assertThat(membership.createdAt()).isEqualTo(CREATED_AT);
		assertThat(membership.updatedAt()).isEqualTo(CREATED_AT);
		assertThat(membership.isActive()).isTrue();
	}

	@Test
	void removesAndReactivatesAMembershipIdempotently() {
		OrganizationMembership active = activeMembership();
		Instant removedAt = CREATED_AT.plusSeconds(60);

		assertThat(active.activate(removedAt)).isSameAs(active);

		OrganizationMembership removed = active.remove(removedAt);
		assertThat(removed.status()).isEqualTo(OrganizationMembershipStatus.REMOVED);
		assertThat(removed.version()).isOne();
		assertThat(removed.updatedAt()).isEqualTo(removedAt);
		assertThat(removed.isActive()).isFalse();
		assertThat(removed.tenantId()).isEqualTo(active.tenantId());
		assertThat(removed.organizationId()).isEqualTo(active.organizationId());
		assertThat(removed.userId()).isEqualTo(active.userId());
		assertThat(removed.createdAt()).isEqualTo(active.createdAt());
		assertThat(removed.remove(removedAt.plusSeconds(1))).isSameAs(removed);

		OrganizationMembership reactivated = removed.activate(removedAt.plusSeconds(2));
		assertThat(reactivated.status()).isEqualTo(OrganizationMembershipStatus.ACTIVE);
		assertThat(reactivated.version()).isEqualTo(2);
		assertThat(reactivated.updatedAt()).isEqualTo(removedAt.plusSeconds(2));
	}

	@Test
	void keepsTransitionTimeMonotonicWhenTheClockMovesBackward() {
		OrganizationMembership removed = activeMembership().remove(CREATED_AT.minusSeconds(1));

		assertThat(removed.updatedAt()).isEqualTo(CREATED_AT);
	}

	@Test
	void rejectsInvalidStoredStateAndTransitions() {
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, -1, CREATED_AT, CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT.minusSeconds(1)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> activeMembership().remove(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(null, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, null, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, null,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, null, 0,
				CREATED_AT, CREATED_AT)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, null, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, 0, CREATED_AT, null))
			.isInstanceOf(NullPointerException.class);
		OrganizationMembership maximumVersion = new OrganizationMembership(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID,
				OrganizationMembershipStatus.ACTIVE, Long.MAX_VALUE, CREATED_AT, CREATED_AT);
		assertThatThrownBy(() -> maximumVersion.remove(CREATED_AT)).isInstanceOf(ArithmeticException.class);
	}

	@Test
	void validatesPublicMembershipExceptionContext() {
		OrganizationMembershipNotFoundException missing =
				new OrganizationMembershipNotFoundException(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID);
		OrganizationMembershipNotActiveException inactive = new OrganizationMembershipNotActiveException(
				TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, OrganizationMembershipStatus.REMOVED);
		OrganizationMembershipConcurrentUpdateException concurrent =
				new OrganizationMembershipConcurrentUpdateException(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, 7);

		assertThat(missing.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(missing.organizationId()).isEqualTo(ORGANIZATION_ID);
		assertThat(missing.userId()).isEqualTo(USER_ID);
		assertThat(inactive.status()).isEqualTo(OrganizationMembershipStatus.REMOVED);
		assertThat(concurrent.expectedVersion()).isEqualTo(7);
		assertThatThrownBy(() -> new OrganizationMembershipNotActiveException(TenantId.DEFAULT, ORGANIZATION_ID,
				USER_ID, OrganizationMembershipStatus.ACTIVE)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new OrganizationMembershipConcurrentUpdateException(TenantId.DEFAULT,
				ORGANIZATION_ID, USER_ID, -1)).isInstanceOf(IllegalArgumentException.class);
	}

	private OrganizationMembership activeMembership() {
		return OrganizationMembership.active(TenantId.DEFAULT, ORGANIZATION_ID, USER_ID, CREATED_AT);
	}

}
