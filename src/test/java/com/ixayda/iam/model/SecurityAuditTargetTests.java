package com.ixayda.iam.model;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.*;

class SecurityAuditTargetTests {

	private static final SecurityAuditContext CONTEXT = new SecurityAuditContext("system:test", "internal:test", UUID.randomUUID());

	@ParameterizedTest
	@EnumSource(value = SecurityAuditEvent.Action.class, names = { "RESOURCE_CREATED", "RESOURCE_UPDATED", "RESOURCE_DISABLED", "RESOURCE_ENABLED", "RESOURCE_ROLE_CREATED", "RESOURCE_ROLE_UPDATED", "RESOURCE_ROLE_DISABLED", "RESOURCE_ROLE_ENABLED" })
	void objectActionsRequireTheObjectTargetAndCannotMasqueradeAsUserActions(SecurityAuditEvent.Action action) {
		var target = new SecurityAuditTarget(action.targetType(), UUID.randomUUID());
		assertThat(new SecurityAuditEvent(UUID.randomUUID(), action, null, CONTEXT, target).target()).isEqualTo(target);
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, null, CONTEXT));
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), action, target.id(), CONTEXT, target));
	}

	@Test
	void userActionsAndObjectTargetsRemainSeparate() {
		var target = new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, UUID.randomUUID());
		assertThatIllegalArgumentException().isThrownBy(() -> new SecurityAuditEvent(UUID.randomUUID(), SecurityAuditEvent.Action.USER_CREATED, UUID.randomUUID(), CONTEXT, target));
		assertThatThrownBy(() -> new SecurityAuditTarget(null, UUID.randomUUID())).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SecurityAuditTarget(SecurityAuditTarget.Type.RESOURCE, null)).isInstanceOf(NullPointerException.class);
	}

}
