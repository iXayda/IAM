package com.ixayda.iam.model;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.*;

class SecurityAuditTargetTests {

	private static final SecurityAuditContext CONTEXT = new SecurityAuditContext("system:test", "internal:test", UUID.randomUUID());

	@ParameterizedTest
	@EnumSource(value = SecurityAuditEvent.Action.class, names = { "RESOURCE_CREATED", "RESOURCE_UPDATED", "RESOURCE_DISABLED", "RESOURCE_ENABLED", "RESOURCE_ROLE_CREATED", "RESOURCE_ROLE_UPDATED", "RESOURCE_ROLE_DISABLED", "RESOURCE_ROLE_ENABLED", "CLIENT_CREATED", "CLIENT_UPDATED", "CLIENT_DISABLED", "CLIENT_ENABLED", "CLIENT_SECRET_ROTATED" })
	void objectActionsRequireTheObjectTargetAndCannotMasqueradeAsUserActions(SecurityAuditEvent.Action action) {
		var target = new SecurityAuditTarget(action.targetType(), UUID.randomUUID());
		assertThat(new SecurityAuditEvent(UUID.randomUUID(), action, null, CONTEXT, target).target()).isEqualTo(target);
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, null, CONTEXT));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, target.id(), CONTEXT, target));
	}

	@ParameterizedTest
	@EnumSource(value = SecurityAuditEvent.Action.class, names = { "USER_ROLE_GRANTED", "USER_ROLE_REVOKED" })
	void bindingActionsRequireBothTheUserAndTheBusinessRole(SecurityAuditEvent.Action action) {
		UUID user = UUID.randomUUID();
		var target = new SecurityAuditTarget(SecurityAuditTarget.Type.ROLE, UUID.randomUUID());
		assertThat(new SecurityAuditEvent(UUID.randomUUID(), action, user, CONTEXT, target).targetUserId()).isEqualTo(user);
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, null, CONTEXT, target));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, user, CONTEXT));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, user, CONTEXT,
				new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, target.id())));
	}

	@Test
	void userActionsAndObjectTargetsRemainSeparate() {
		var target = new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, UUID.randomUUID());
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), SecurityAuditEvent.Action.USER_CREATED, UUID.randomUUID(), CONTEXT, target));
		assertThatThrownBy(() -> new SecurityAuditTarget(null, UUID.randomUUID())).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, null)).isInstanceOf(NullPointerException.class);
	}

}
