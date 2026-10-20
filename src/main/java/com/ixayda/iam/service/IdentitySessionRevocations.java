package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Trusted primitive: the caller authorizes the operation and holds the target user before any session or native locks. */
@Service
class IdentitySessionRevocations {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationRevocations authorizations;
	private final SecurityAudits audits;

	IdentitySessionRevocations(IdentityUsers users, IdentityBrowserSessions sessions, IdentityAuthorizationRevocations authorizations, SecurityAudits audits) {
		this.users = users; this.sessions = sessions; this.authorizations = authorizations; this.audits = audits;
	}

	@Transactional(propagation = Propagation.MANDATORY)
	public void revokeForUser(UUID userId, SecurityAuditContext audit) {
		Assert.notNull(userId, "User id is required"); Assert.notNull(audit, "Trusted audit context is required");
		// Advancing the epoch also rejects password evidence validated before this transaction but saved afterwards.
		this.users.passwordVersion(userId).ifPresent(version -> this.users.invalidateAuthentications(userId, version));
		this.sessions.revokeAll(userId, audit);
		this.authorizations.revokeForUser(userId, audit);
		this.audits.recordSuccess(Action.ALL_SESSIONS_REVOKED, userId, audit);
	}
}
