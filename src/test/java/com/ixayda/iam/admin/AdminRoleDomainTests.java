package com.ixayda.iam.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class AdminRoleDomainTests {

	private static final Instant NOW = Instant.parse("2026-07-20T00:00:00Z");

	private static final UserId SUBJECT = new UserId(UUID.fromString("019d2da6-2f53-79e1-8001-93b777265201"));

	private static final UserId ACTOR = new UserId(UUID.fromString("019d2da6-2f53-79e1-8001-93b777265202"));

	@Test
	void createsBootstrapPermanentAndBoundedJitBindings() {
		AdminRoleBinding bootstrap = AdminRoleBinding.bootstrap(TenantId.DEFAULT, SUBJECT, NOW);
		AdminRoleBinding permanent = AdminRoleBinding.permanent(TenantId.DEFAULT, SUBJECT,
				AdminRoleCode.from("support"), ACTOR, "  Support rotation  ", NOW);
		AdminRoleBinding jit = AdminRoleBinding.justInTime(TenantId.DEFAULT, SUBJECT,
				AdminRoleCode.from("auditor"), ACTOR, "  Incident review  ", NOW.plusSeconds(60), NOW);

		assertThat(bootstrap.createdByUserId()).isNull();
		assertThat(bootstrap.roleCode()).isEqualTo(AdminRoleCode.SUPER_ADMIN);
		assertThat(permanent.reason()).isEqualTo("Support rotation");
		assertThat(jit.reason()).isEqualTo("Incident review");
		assertThat(jit.isEffectiveAt(NOW.plusSeconds(59))).isTrue();
		assertThat(jit.isEffectiveAt(NOW.plusSeconds(60))).isFalse();
	}

	@Test
	void revokesBindingsMonotonicallyAndOnlyOnce() {
		AdminRoleBinding active = AdminRoleBinding.permanent(TenantId.DEFAULT, SUBJECT,
				AdminRoleCode.from("support"), ACTOR, null, NOW);
		UserId revoker = new UserId(UUID.fromString("019d2da6-2f53-79e1-8001-93b777265203"));

		AdminRoleBinding revoked = active.revoke(revoker, NOW.minusSeconds(1));

		assertThat(revoked.status()).isEqualTo(AdminRoleBindingStatus.REVOKED);
		assertThat(revoked.version()).isOne();
		assertThat(revoked.updatedAt()).isEqualTo(NOW);
		assertThat(revoked.revokedAt()).isEqualTo(NOW);
		assertThat(revoked.revoke(revoker, NOW.plusSeconds(1))).isSameAs(revoked);
		assertThat(revoked.isEffectiveAt(NOW)).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "Role", "role-name", "role.name", "ab", " role", "role " })
	void rejectsInvalidRoleCodes(String value) {
		assertThatThrownBy(() -> AdminRoleCode.from(value)).isInstanceOf(IllegalArgumentException.class);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", " ", "invalid", "Invalid.read", "user.read ", "user..read" })
	void rejectsInvalidPermissionCodes(String value) {
		assertThatThrownBy(() -> AdminPermissionCode.from(value)).isInstanceOfAny(NullPointerException.class,
				IllegalArgumentException.class);
	}

	@Test
	void rejectsSelfGrantsAndInvalidJitLifetimes() {
		AdminRoleCode support = AdminRoleCode.from("support");
		assertThatThrownBy(
				() -> AdminRoleBinding.permanent(TenantId.DEFAULT, SUBJECT, support, SUBJECT, null, NOW))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> AdminRoleBinding.justInTime(TenantId.DEFAULT, SUBJECT, support, ACTOR,
				null, NOW.plusSeconds(1), NOW)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> AdminRoleBinding.justInTime(TenantId.DEFAULT, SUBJECT, support, ACTOR,
				"Incident", NOW, NOW)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> AdminRoleBinding.justInTime(TenantId.DEFAULT, SUBJECT, support, ACTOR,
				"Incident", NOW.plus(AdminRoleBinding.MAXIMUM_JIT_DURATION).plusNanos(1), NOW))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
