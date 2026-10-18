package com.ixayda.iam.service;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityAdministratorRepository;
import com.ixayda.iam.repository.IdentityBrowserSessionRepository;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.SerializationUtils;

/** Rebuilds fixed management permissions from server evidence and current database state on every request. */
@Service
public class IdentityAdministratorSessions {

	public static final String AUTHENTICATION = "iam.administratorAuthentication";
	public static final String TOTP_AUTHORITY = "FACTOR_TOTP";
	public static final String ADMINISTRATOR_AUTHORITY = "ROLE_IAM_ADMIN";
	private static final long MFA_SECONDS = 900;

	private final IdentityAdministratorRepository administrators;
	private final IdentityBrowserSessionRepository sessions;
	private final SecurityAudits audits;

	IdentityAdministratorSessions(IdentityAdministratorRepository administrators,
			IdentityBrowserSessionRepository sessions, SecurityAudits audits) {
		this.administrators = administrators;
		this.sessions = sessions;
		this.audits = audits;
	}

	public boolean isAdministrator(UUID userId) {
		return userId != null && this.administrators.find(userId).isPresent();
	}

	public List<GrantedAuthority> authorities(UUID userId, Object passwordAuthenticatedAt, Object evidence) {
		if (!(passwordAuthenticatedAt instanceof Long passwordTime) || passwordTime <= 0 || passwordTime > System.currentTimeMillis()) {
			return List.of();
		}
		if (!(evidence instanceof IdentityAdministratorAuthentication verified)
				|| !verified.userId().equals(userId) || verified.passwordAuthenticatedAt() != passwordTime
				|| !isCurrent(verified)) {
			return List.of();
		}
		var password = FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
				.issuedAt(Instant.ofEpochMilli(passwordTime)).build();
		return List.of(password, FactorGrantedAuthority.withAuthority(TOTP_AUTHORITY).issuedAt(verified.verifiedAt()).build(),
				new SimpleGrantedAuthority(ADMINISTRATOR_AUTHORITY));
	}

	private boolean isCurrent(IdentityAdministratorAuthentication verified) {
		Instant now = Instant.now();
		return !verified.verifiedAt().isAfter(now) && verified.verifiedAt().plusSeconds(MFA_SECONDS).isAfter(now)
				&& verified.verifiedAt().toEpochMilli() >= verified.passwordAuthenticatedAt()
				&& this.administrators.hasCurrentAuthentication(verified.userId(), verified.factorId(), verified.credentialVersion());
	}

	/** Called inside the authentication transaction, after the HTTP adapter has flushed the official session repository. */
	@Transactional(propagation = Propagation.MANDATORY)
	void requireStored(String originalId, String sessionId, IdentityAdministratorAuthentication evidence) {
		if (!isCurrent(evidence) || this.sessions.ownedAndUnexpired(originalId, evidence.userId())
				|| !this.sessions.ownedAndUnexpired(sessionId, evidence.userId())
				|| !Arrays.equals(this.sessions.attribute(sessionId, AUTHENTICATION), SerializationUtils.serialize(evidence))) {
			throw new IllegalStateException("Administrator authentication was not stored");
		}
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW)
	public void recordAccessDenied(UUID userId, UUID correlationId) {
		this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, userId,
				new SecurityAuditContext(userId == null ? "anonymous" : "user:" + userId, "browser:admin", correlationId));
	}

}
