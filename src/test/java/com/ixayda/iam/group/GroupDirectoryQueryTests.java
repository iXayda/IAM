package com.ixayda.iam.group;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GroupDirectoryQueryTests {

	@Test
	void createsBoundedDirectoryCriteria() {
		GroupId groupId = GroupId.random();

		assertThat(GroupDirectoryQuery.all(1, 10).criterion()).isInstanceOf(GroupDirectoryQuery.All.class);
		assertThat(GroupDirectoryQuery.none(1, 10).criterion()).isInstanceOf(GroupDirectoryQuery.None.class);
		assertThat(GroupDirectoryQuery.idEquals(1, 10, groupId).criterion())
			.isEqualTo(new GroupDirectoryQuery.IdEquals(groupId));
		assertThat(GroupDirectoryQuery.displayNameEquals(1, 10, "Engineering").criterion())
			.isEqualTo(new GroupDirectoryQuery.DisplayNameEquals("Engineering"));
	}

	@Test
	void rejectsInvalidDirectoryQueriesAndPages() {
		assertThatThrownBy(() -> GroupDirectoryQuery.all(-1, 10)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> GroupDirectoryQuery.all(0, -1)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> GroupDirectoryQuery.all(0, GroupDirectoryQuery.MAX_LIMIT + 1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new GroupDirectoryQuery(0, 10, null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> GroupDirectoryQuery.idEquals(0, 10, null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> GroupDirectoryQuery.displayNameEquals(0, 10, null))
			.isInstanceOf(NullPointerException.class);

		assertThat(new GroupPage(2, List.of())).isEqualTo(new GroupPage(2, List.of()));
		assertThatThrownBy(() -> new GroupPage(-1, List.of())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new GroupPage(0, java.util.Collections.singletonList(null)))
			.isInstanceOf(NullPointerException.class);
	}

}
