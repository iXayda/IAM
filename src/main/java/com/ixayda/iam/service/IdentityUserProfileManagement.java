package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

/** Administrator profile changes share the current-session, fresh-TOTP and ordered user-lock boundary. */
@Service
public class IdentityUserProfileManagement {

	private final IdentityAdministratorOperations operations;
	private final IdentityUsers users;
	private final SecurityAudits audits;

	IdentityUserProfileManagement(IdentityAdministratorOperations operations, IdentityUsers users, SecurityAudits audits) {
		this.operations = operations;
		this.users = users;
		this.audits = audits;
	}

	public Status updateDisplayName(IdentityAdministratorContext context, UUID targetId, String displayName,
			String code, Runnable persistSession) {
		Assert.notNull(targetId, "Target user id is required");
		String normalized;
		try { normalized = IdentityUsers.normalizeDisplayName(displayName); }
		catch (IllegalArgumentException ex) { return Status.INVALID_INPUT; }
		var result = this.operations.execute(context, targetId, code, persistSession, audit -> {
			var target = this.users.findById(targetId);
			if (target.isEmpty()) { return Status.NOT_FOUND; }
			if (target.orElseThrow().displayName().equals(normalized)) { return Status.UNCHANGED; }
			this.users.updateDisplayName(targetId, normalized);
			this.audits.recordSuccess(Action.USER_PROFILE_UPDATED, targetId, audit);
			return Status.UPDATED;
		});
		return switch (result.status()) {
			case COMPLETED -> result.value();
			case INVALID_SESSION -> Status.INVALID_SESSION;
			case FORBIDDEN -> Status.FORBIDDEN;
			case REJECTED -> Status.REJECTED;
			case THROTTLED -> Status.THROTTLED;
		};
	}

	public enum Status { UPDATED, UNCHANGED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, NOT_FOUND }

}
