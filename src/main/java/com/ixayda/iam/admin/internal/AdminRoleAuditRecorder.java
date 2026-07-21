package com.ixayda.iam.admin.internal;

import java.util.Map;
import java.util.Locale;

import com.ixayda.iam.admin.AdminRoleBinding;
import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.audit.AuditEventType;
import com.ixayda.iam.user.UserId;
import org.springframework.stereotype.Component;

@Component
class AdminRoleAuditRecorder {

	private static final String SOURCE = "administration";

	private static final AuditEventType ROLE_GRANTED = AuditEventType.from("administration.role.granted");

	private static final AuditEventType ROLE_REVOKED = AuditEventType.from("administration.role.revoked");

	private final AuditEventOperations events;

	AdminRoleAuditRecorder(AuditEventOperations events) {
		this.events = events;
	}

	void granted(AdminRoleBinding binding) {
		append(ROLE_GRANTED, binding.createdByUserId(), binding, binding.createdAt());
	}

	void revoked(AdminRoleBinding binding) {
		append(ROLE_REVOKED, binding.revokedByUserId(), binding, binding.revokedAt());
	}

	private void append(AuditEventType type, UserId actorUserId, AdminRoleBinding binding,
			java.time.Instant occurredAt) {
		this.events.append(new AppendAuditEvent(binding.tenantId(), type, AuditEventOutcome.SUCCEEDED, actorUserId,
				binding.userId(), null, null, SOURCE, occurredAt,
				Map.of("role", binding.roleCode().value(), "binding_type",
						binding.type().name().toLowerCase(Locale.ROOT))));
	}

}
