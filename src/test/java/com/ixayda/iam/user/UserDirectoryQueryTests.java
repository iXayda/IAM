package com.ixayda.iam.user;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UserDirectoryQueryTests {

	@Test
	void createsBoundedDirectoryCriteria() {
		UserId userId = UserId.random();

		assertThat(UserDirectoryQuery.all(1, 10).criterion()).isInstanceOf(UserDirectoryQuery.All.class);
		assertThat(UserDirectoryQuery.none(1, 10).criterion()).isInstanceOf(UserDirectoryQuery.None.class);
		assertThat(UserDirectoryQuery.idEquals(1, 10, userId).criterion())
			.isEqualTo(new UserDirectoryQuery.IdEquals(userId));
		assertThat(UserDirectoryQuery.primaryIdentifierEquals(1, 10, "alice").criterion())
			.isEqualTo(new UserDirectoryQuery.PrimaryIdentifierEquals("alice"));
	}

	@Test
	void rejectsInvalidDirectoryQueriesAndPages() {
		assertThatThrownBy(() -> UserDirectoryQuery.all(-1, 10)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> UserDirectoryQuery.all(0, -1)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> UserDirectoryQuery.all(0, UserDirectoryQuery.MAX_LIMIT + 1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new UserDirectoryQuery(0, 10, null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> UserDirectoryQuery.idEquals(0, 10, null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> UserDirectoryQuery.primaryIdentifierEquals(0, 10, null))
			.isInstanceOf(NullPointerException.class);

		assertThat(new UserPage(2, List.of())).isEqualTo(new UserPage(2, List.of()));
		assertThatThrownBy(() -> new UserPage(-1, List.of())).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new UserPage(0, java.util.Collections.singletonList(null)))
			.isInstanceOf(NullPointerException.class);
	}

}
