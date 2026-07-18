package com.ixayda.iam.group;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class GroupMembershipTests {

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f141"));

	private static final UserId USER_ID =
			new UserId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f142"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void preservesTheTenantScopedRelationship() {
		GroupMembership membership = new GroupMembership(TenantId.DEFAULT, GROUP_ID, USER_ID, CREATED_AT);

		assertThat(membership.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(membership.groupId()).isEqualTo(GROUP_ID);
		assertThat(membership.userId()).isEqualTo(USER_ID);
		assertThat(membership.createdAt()).isEqualTo(CREATED_AT);
	}

	@Test
	void rejectsMissingRelationshipData() {
		assertThatNullPointerException()
			.isThrownBy(() -> new GroupMembership(null, GROUP_ID, USER_ID, CREATED_AT));
		assertThatNullPointerException()
			.isThrownBy(() -> new GroupMembership(TenantId.DEFAULT, null, USER_ID, CREATED_AT));
		assertThatNullPointerException()
			.isThrownBy(() -> new GroupMembership(TenantId.DEFAULT, GROUP_ID, null, CREATED_AT));
		assertThatNullPointerException()
			.isThrownBy(() -> new GroupMembership(TenantId.DEFAULT, GROUP_ID, USER_ID, null));
	}

}
