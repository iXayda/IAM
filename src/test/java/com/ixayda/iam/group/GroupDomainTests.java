package com.ixayda.iam.group;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class GroupDomainTests {

	private static final GroupId GROUP_ID =
			new GroupId(UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f101"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	@Test
	void usesUuidBackedGroupIds() {
		assertThat(GroupId.from(GROUP_ID.toString())).isEqualTo(GROUP_ID);
		assertThat(GroupId.random().value()).isNotNull();
	}

	@Test
	void normalizesDisplayNamesWithoutExposingThemInDiagnostics() {
		CreateGroupRequest request = new CreateGroupRequest("  Platform Administrators  ");
		Group group = group(request.displayName(), GroupStatus.ACTIVE, 0, CREATED_AT);

		assertThat(request.displayName()).isEqualTo("Platform Administrators");
		assertThat(request.toString()).doesNotContain(request.displayName());
		assertThat(group.toString()).doesNotContain(group.displayName());
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "   ", "\nAdministrators", "Administrators\n" })
	void rejectsInvalidDisplayNames(String value) {
		assertThatThrownBy(() -> new CreateGroupRequest(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void countsUnicodeCodePointsInDisplayNames() {
		String supplementaryCharacter = "\uD83D\uDE00";

		assertThat(new CreateGroupRequest(supplementaryCharacter.repeat(200)).displayName()).hasSize(400);
		assertThatThrownBy(() -> new CreateGroupRequest(supplementaryCharacter.repeat(201)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void updatesDisplayNamesAndDeletesMonotonically() {
		Group original = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);

		assertThat(original.updateDisplayName(" Engineering ", CREATED_AT.plusSeconds(1))).isSameAs(original);
		Group renamed = original.updateDisplayName("Platform", CREATED_AT.plusSeconds(1));
		assertThat(renamed.displayName()).isEqualTo("Platform");
		assertThat(renamed.version()).isOne();
		assertThat(renamed.updatedAt()).isEqualTo(CREATED_AT.plusSeconds(1));
		assertThat(renamed.tenantId()).isEqualTo(original.tenantId());

		Group deleted = renamed.delete(CREATED_AT.plusSeconds(2));
		assertThat(deleted.isDeleted()).isTrue();
		assertThat(deleted.version()).isEqualTo(2);
		assertThat(deleted.delete(CREATED_AT.plusSeconds(3))).isSameAs(deleted);
		assertThatThrownBy(() -> deleted.updateDisplayName("Restored", CREATED_AT.plusSeconds(3)))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void advancesTheDirectoryRevisionWhenMembersChange() {
		Group original = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT);

		Group changed = original.membersChanged(CREATED_AT.plusSeconds(1));

		assertThat(changed.id()).isEqualTo(original.id());
		assertThat(changed.tenantId()).isEqualTo(original.tenantId());
		assertThat(changed.displayName()).isEqualTo(original.displayName());
		assertThat(changed.status()).isEqualTo(GroupStatus.ACTIVE);
		assertThat(changed.version()).isOne();
		assertThat(changed.updatedAt()).isEqualTo(CREATED_AT.plusSeconds(1));
	}

	@Test
	void replacesTheDisplayNameAndMembersWithOneDirectoryRevision() {
		Group original = group("Engineering", GroupStatus.ACTIVE, 4, CREATED_AT);
		UserId memberId = UserId.random();
		ReplaceGroupRequest request = new ReplaceGroupRequest(" Platform ", Set.of(memberId));

		Group replaced = original.replace(request.displayName(), true, CREATED_AT.plusSeconds(1));

		assertThat(replaced.displayName()).isEqualTo("Platform");
		assertThat(replaced.version()).isEqualTo(5);
		assertThat(replaced.updatedAt()).isEqualTo(CREATED_AT.plusSeconds(1));
		assertThat(request.toString()).doesNotContain("Platform", memberId.toString());
		assertThat(replaced.replace(" Platform ", false, CREATED_AT.plusSeconds(2))).isSameAs(replaced);
	}

	@Test
	void rejectsMemberChangesForDeletedGroupsAndRegressingTime() {
		Group active = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT.plusSeconds(1));
		Group deleted = active.delete(CREATED_AT.plusSeconds(2));

		assertThatThrownBy(() -> active.membersChanged(CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> deleted.membersChanged(CREATED_AT.plusSeconds(3)))
			.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void rejectsInvalidEntityStateAndRegressingTime() {
		assertThatThrownBy(() -> group("Engineering", GroupStatus.ACTIVE, -1, CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new Group(GROUP_ID, TenantId.DEFAULT, "Engineering", GroupStatus.ACTIVE, 0,
				CREATED_AT, CREATED_AT.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
		Group active = group("Engineering", GroupStatus.ACTIVE, 0, CREATED_AT.plusSeconds(1));
		assertThatThrownBy(() -> active.updateDisplayName("Platform", CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> active.delete(CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
	}

	private Group group(String displayName, GroupStatus status, long version, Instant updatedAt) {
		return new Group(GROUP_ID, TenantId.DEFAULT, displayName, status, version, CREATED_AT, updatedAt);
	}

}
