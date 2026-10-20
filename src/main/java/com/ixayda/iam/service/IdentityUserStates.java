package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Internal lifecycle workflows; trusted callers authorize the operation and supply audit attribution. */
@Service
public class IdentityUserStates {

	private final IdentityUsers users;
	private final IdentityUserSetups setups;
	private final IdentityPasswordRecoveries recoveries;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationRevocations revocations;
	private final IdentityAdministrators administrators;
	private final SecurityAudits audits;

	IdentityUserStates(IdentityUsers users, IdentityUserSetups setups, IdentityPasswordRecoveries recoveries,
			IdentityBrowserSessions sessions, IdentityAuthorizationRevocations revocations, IdentityAdministrators administrators, SecurityAudits audits) {
		this.users = users;
		this.setups = setups;
		this.recoveries = recoveries;
		this.sessions = sessions;
		this.revocations = revocations;
		this.administrators = administrators;
		this.audits = audits;
	}

	@Transactional
	public Result disable(UUID userId, SecurityAuditContext audit) {
		validate(userId, audit);
		if (this.users.lockById(userId).status() == IdentityUser.Status.DISABLED) {
			return Result.UNCHANGED;
		}
		if (!this.administrators.allowDisable(userId, audit)) {
			return Result.LAST_ADMINISTRATOR_PROTECTED;
		}
		this.users.disable(userId);
		this.setups.cancelOutstanding(userId, audit);
		this.recoveries.cancelOutstanding(userId, audit);
		this.sessions.revokeAll(userId, audit);
		this.revocations.revokeForUser(userId, audit);
		this.audits.recordSuccess(Action.USER_DISABLED, userId, audit);
		return Result.CHANGED;
	}

	@Transactional
	public Result enable(UUID userId, SecurityAuditContext audit) {
		validate(userId, audit);
		if (this.users.lockById(userId).status() != IdentityUser.Status.DISABLED) {
			return Result.UNCHANGED;
		}
		this.users.enable(userId);
		this.revocations.revokeForUser(userId, audit);
		this.audits.recordSuccess(Action.USER_ENABLED, userId, audit);
		return Result.CHANGED;
	}

	private static void validate(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required");
		Assert.notNull(audit, "Trusted audit context is required");
	}

	public enum Result {
		CHANGED, UNCHANGED, LAST_ADMINISTRATOR_PROTECTED
	}

}
