package com.ixayda.iam.audit.internal;

import java.util.Map;

import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditAuthenticationFactor;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.audit.AuditEventType;
import com.ixayda.iam.credential.CredentialSecurityEvent;
import com.ixayda.iam.session.UserSessionRevokedEvent;
import com.ixayda.iam.user.UserSecurityEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
class SecurityLifecycleAuditRecorder {

	private static final String CREDENTIAL_SOURCE = "credential";

	private static final String SESSION_SOURCE = "session";

	private static final String USER_SOURCE = "user";

	private final AuditEventOperations events;

	SecurityLifecycleAuditRecorder(AuditEventOperations events) {
		this.events = events;
	}

	@EventListener
	void record(CredentialSecurityEvent event) {
		AuditEventType type = switch (event.type()) {
			case TOTP_ACTIVATED -> AuditEventType.from("credential.totp.activated");
			case TOTP_REVOKED -> AuditEventType.from("credential.totp.revoked");
			case RECOVERY_CODES_REPLACED -> AuditEventType.from("credential.recovery_codes.replaced");
			case RECOVERY_CODE_CONSUMED -> AuditEventType.from("credential.recovery_code.consumed");
		};
		AuditAuthenticationFactor factor = switch (event.type()) {
			case TOTP_ACTIVATED, TOTP_REVOKED -> AuditAuthenticationFactor.TOTP;
			case RECOVERY_CODES_REPLACED, RECOVERY_CODE_CONSUMED -> AuditAuthenticationFactor.RECOVERY_CODE;
		};
		Map<String, String> attributes = event.totpCredentialId() == null ? Map.of()
				: Map.of("credential_id", event.totpCredentialId().toString());
		this.events.append(new AppendAuditEvent(event.tenantId(), type, AuditEventOutcome.SUCCEEDED, event.userId(),
				null, factor, CREDENTIAL_SOURCE, event.occurredAt(), attributes));
	}

	@EventListener
	void record(UserSessionRevokedEvent event) {
		this.events.append(new AppendAuditEvent(event.tenantId(), AuditEventType.from("session.revoked"),
				AuditEventOutcome.SUCCEEDED, event.userId(), event.sessionId(), null, SESSION_SOURCE,
				event.occurredAt(), Map.of()));
	}

	@EventListener
	void record(UserSecurityEvent event) {
		String transition = event.type().name().toLowerCase(java.util.Locale.ROOT);
		this.events.append(new AppendAuditEvent(event.tenantId(), AuditEventType.from("user.lifecycle." + transition),
				AuditEventOutcome.SUCCEEDED, event.userId(), null, null, USER_SOURCE, event.occurredAt(), Map.of()));
	}

}
