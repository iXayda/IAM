package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.Test;

class UserIdTests {

	private static final UUID VALUE = UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc5");

	@Test
	void createsUuidBackedUserIds() {
		UserId userId = new UserId(VALUE);

		assertThat(UserId.from(userId.toString())).isEqualTo(userId);
		assertThat(UserId.random().value()).isNotNull();
	}

	@Test
	void rejectsNullValues() {
		assertThatThrownBy(() -> new UserId(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> UserId.from(null)).isInstanceOf(NullPointerException.class);
	}

}
