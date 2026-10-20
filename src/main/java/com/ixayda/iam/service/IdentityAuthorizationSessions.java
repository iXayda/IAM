package com.ixayda.iam.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAuthorizationSession;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Browser grant projection; locks remain held by the enclosing authorization and mandatory-audit transaction. */
@Service
@Lazy
public class IdentityAuthorizationSessions {

	private final IdentityApplicationRoles applications;
	private final IdentityBrowserSessions sessions;

	IdentityAuthorizationSessions(IdentityApplicationRoles applications, IdentityBrowserSessions sessions) {
		this.applications = applications; this.sessions = sessions;
	}

	/** Call before any subject, catalog, session or authorization locks. Never publish this context before commit. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<IdentityAuthorizationSession> projectForIssuance(UUID userId, String sessionId, long authenticatedAt,
			long credentialVersion, IdentityProtocolClients.Snapshot client) {
		var access = this.applications.projectForBrowserIssuance(userId, credentialVersion, client);
		if (access.isEmpty()) { return Optional.empty(); }
		return this.sessions.lockForAuthorization(userId, sessionId, authenticatedAt, credentialVersion)
				.map(session -> new IdentityAuthorizationSession(access.orElseThrow(), session.id(), session.authenticatedAt(),
						session.idleExpiresAt(), session.absoluteExpiresAt()));
	}

	/** Subject and catalog proof must already be locked; even an expired source is locked before native state. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<Instant> exchangeDeadline(IdentityAuthorizationSession original) {
		return this.sessions.exchangeDeadline(original);
	}

}
