package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Updates the caller's profile only while its persisted browser authentication remains valid. */
@Service
public class IdentityProfiles {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final SecurityAudits audits;

	IdentityProfiles(IdentityUsers users, IdentityBrowserSessions sessions, SecurityAudits audits) {
		this.users = users;
		this.sessions = sessions;
		this.audits = audits;
	}

	/** Identity, session evidence and correlation id come from the trusted entry, never form fields. */
	@Transactional
	public Result updateDisplayName(UUID userId, String sessionId, long credentialVersion, long authenticatedAt,
			String displayName, UUID correlationId) {
		Assert.notNull(userId, "Authenticated user id is required");
		Assert.hasText(sessionId, "Authenticated session id is required");
		Assert.notNull(correlationId, "Correlation id is required");
		String normalized;
		try {
			normalized = IdentityUsers.normalizeDisplayName(displayName);
		}
		catch (IllegalArgumentException ex) {
			return Result.INVALID_DISPLAY_NAME;
		}
		IdentityUser user = this.users.lockById(userId);
		var expiry = this.sessions.lockOwnedSessionExpiry(userId, sessionId);
		if (user.status() != IdentityUser.Status.ACTIVE
				|| expiry.isEmpty()
				|| !this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)) {
			return Result.INVALID_SESSION;
		}
		if (user.displayName().equals(normalized)) {
			return Result.UNCHANGED;
		}
		this.users.updateDisplayName(userId, normalized);
		this.audits.recordSuccess(Action.USER_PROFILE_UPDATED, userId,
				new SecurityAuditContext("user:" + userId, "browser:profile-change", correlationId));
		if (!this.sessions.isAuthenticationCurrent(userId, authenticatedAt, credentialVersion)
				|| !this.sessions.isWithinSessionDeadline(authenticatedAt, expiry.orElseThrow())) {
			throw new IllegalStateException("Password session expired during profile update");
		}
		return Result.UPDATED;
	}

	public enum Result {
		UPDATED, UNCHANGED, INVALID_DISPLAY_NAME, INVALID_SESSION
	}

}
