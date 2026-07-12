package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class UserTests {

	private static final UserId USER_ID =
			new UserId(UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0cc5"));

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final Instant UPDATED_AT = CREATED_AT.plusSeconds(10);

	private static final Instant LAST_LOGIN_AT = CREATED_AT.plusSeconds(5);

	private static final LoginIdentifier USERNAME = LoginIdentifier.username("alice");

	@ParameterizedTest
	@MethodSource("statusTransitions")
	void enforcesTheCompleteStatusTransitionMatrix(UserStatus source, UserStatus target, boolean allowed) {
		User original = user(source);
		Instant changedAt = UPDATED_AT.plusSeconds(60);

		if (source == target) {
			assertThat(transition(original, target, changedAt)).isSameAs(original);
		}
		else if (allowed) {
			User changed = transition(original, target, changedAt);

			assertThat(changed.status()).isEqualTo(target);
			assertThat(changed.version()).isEqualTo(original.version() + 1);
			assertThat(changed.updatedAt()).isEqualTo(changedAt);
			assertThat(changed.id()).isEqualTo(original.id());
			assertThat(changed.tenantId()).isEqualTo(original.tenantId());
			assertThat(changed.identifiers()).isEqualTo(original.identifiers());
			assertThat(changed.createdAt()).isEqualTo(original.createdAt());
			assertThat(changed.lastLoginAt()).isEqualTo(original.lastLoginAt());
		}
		else {
			assertThatThrownBy(() -> transition(original, target, changedAt))
				.isInstanceOf(IllegalStateException.class);
		}
	}

	@Test
	void exposesActiveAndDeletedState() {
		assertThat(user(UserStatus.ACTIVE).isActive()).isTrue();
		assertThat(user(UserStatus.DISABLED).isActive()).isFalse();
		assertThat(user(UserStatus.DELETED).isDeleted()).isTrue();
		assertThat(user(UserStatus.LOCKED).isDeleted()).isFalse();
	}

	@Test
	void reportsInvalidTransitionsWithDomainContext() {
		User deleted = user(UserStatus.DELETED);

		assertThatThrownBy(() -> deleted.activate(UPDATED_AT.plusSeconds(1)))
			.isInstanceOf(InvalidUserStatusTransitionException.class)
			.extracting("userId", "source", "target")
			.containsExactly(USER_ID, UserStatus.DELETED, UserStatus.ACTIVE);
	}

	@Test
	void defensivelyCopiesIdentifiers() {
		List<LoginIdentifier> source = new ArrayList<>();
		source.add(USERNAME);
		User user = new User(USER_ID, TenantId.DEFAULT, source, UserStatus.ACTIVE, 0, CREATED_AT, UPDATED_AT,
				LAST_LOGIN_AT);

		source.add(LoginIdentifier.email("alice@example.com"));

		assertThat(user.identifiers()).containsExactly(USERNAME);
		assertThatThrownBy(() -> user.identifiers().add(LoginIdentifier.phone("15551234567")))
			.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	void rejectsInvalidEntityState() {
		assertThatThrownBy(() -> new User(USER_ID, TenantId.DEFAULT, List.of(USERNAME), UserStatus.ACTIVE, -1,
				CREATED_AT, UPDATED_AT, LAST_LOGIN_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new User(USER_ID, TenantId.DEFAULT, List.of(USERNAME), UserStatus.ACTIVE, 0,
				CREATED_AT, CREATED_AT.minusSeconds(1), LAST_LOGIN_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new User(USER_ID, TenantId.DEFAULT, List.of(USERNAME), UserStatus.ACTIVE, 0,
				CREATED_AT, UPDATED_AT, CREATED_AT.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> user(UserStatus.ACTIVE).disable(UPDATED_AT.minusSeconds(1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void keepsLoginValuesOutOfDiagnosticStrings() {
		User user = user(UserStatus.ACTIVE);

		assertThat(user.toString()).doesNotContain(USERNAME.value(), USERNAME.canonicalValue());
	}

	private static Stream<Arguments> statusTransitions() {
		return Stream.of(UserStatus.values()).flatMap(source -> Stream.of(UserStatus.values())
			.map(target -> Arguments.of(source, target, transitionAllowed(source, target))));
	}

	private static boolean transitionAllowed(UserStatus source, UserStatus target) {
		if (source == target) {
			return true;
		}
		return switch (source) {
			case ACTIVE -> target == UserStatus.DISABLED || target == UserStatus.LOCKED || target == UserStatus.DELETED;
			case DISABLED -> target == UserStatus.ACTIVE || target == UserStatus.DELETED;
			case LOCKED -> target == UserStatus.ACTIVE || target == UserStatus.DISABLED || target == UserStatus.DELETED;
			case DELETED -> false;
		};
	}

	private User user(UserStatus status) {
		return new User(USER_ID, TenantId.DEFAULT, List.of(USERNAME), status, 0, CREATED_AT, UPDATED_AT, LAST_LOGIN_AT);
	}

	private User transition(User user, UserStatus target, Instant changedAt) {
		return switch (target) {
			case ACTIVE -> user.activate(changedAt);
			case DISABLED -> user.disable(changedAt);
			case LOCKED -> user.lock(changedAt);
			case DELETED -> user.delete(changedAt);
		};
	}

}
