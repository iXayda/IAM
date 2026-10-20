package com.ixayda.iam.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.PasswordAuthenticationResult;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityBrowserSessionRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.SerializationUtils;

/** Atomic session persistence and audit around Spring Session's storage operations. */
@Service
public class IdentityBrowserSessions {

	public static final String SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";
	public static final String AUTHENTICATED_AT = "iam.authenticatedAt";
	public static final String CREDENTIAL_VERSION = "iam.credentialVersion";
	public static final String LOGIN_PENDING = "iam.loginPending";
	public static final String ORIGINAL_ID = "iam.originalSessionId";
	public static final String MFA_PENDING = "iam.mfaPending";
	public static final String PERSISTENCE_FAILED = "iam.persistenceFailed";
	public static final String TOTP_ENROLLMENT = "iam.totpEnrollment";
	private static final String PERSISTED = "iam.persisted";

	private final IdentityUsers users;
	private final IdentityBrowserSessionRepository repository;
	private final SecurityAudits audits;
	private final IdentityAdministratorSessions administrators;
	private final TransactionTemplate transaction;
	private final TransactionTemplate saveTransaction;
	private final Duration idleTimeout;
	private final Duration absoluteTimeout;

	IdentityBrowserSessions(IdentityUsers users, IdentityBrowserSessionRepository repository, SecurityAudits audits,
			IdentityAdministratorSessions administrators, PlatformTransactionManager manager, @Value("${iam.browser.idle-seconds:1800}") int idleSeconds,
			@Value("${iam.browser.absolute-seconds:28800}") int absoluteSeconds) {
		if (idleSeconds < 1 || idleSeconds > 1800 || absoluteSeconds < idleSeconds || absoluteSeconds > 28800) {
			throw new IllegalArgumentException("Browser session timeouts exceed the supported policy");
		}
		this.users = users;
		this.repository = repository;
		this.audits = audits;
		this.administrators = administrators;
		this.transaction = new TransactionTemplate(manager);
		this.transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		// Normal saves own their transaction; an explicit MFA workflow includes persistence in its transaction.
		this.saveTransaction = new TransactionTemplate(manager);
		this.idleTimeout = Duration.ofSeconds(idleSeconds);
		this.absoluteTimeout = Duration.ofSeconds(absoluteSeconds);
	}

	public Duration idleTimeout() {
		return this.idleTimeout;
	}

	public boolean isAuthenticationCurrent(UUID userId, Object authenticatedAt, Object credentialVersion) {
		return withinAbsoluteLifetime(authenticatedAt) && credentialVersion instanceof Long version
				&& this.users.hasCurrentPasswordVersion(userId, version);
	}

	/** The caller already holds the user's lock before checking its session. */
	@Transactional(propagation = Propagation.MANDATORY)
	boolean lockOwnedSession(UUID userId, String sessionId) {
		return this.repository.lock(sessionId) && this.repository.ownedAndUnexpired(sessionId, userId);
	}

	/** Capture the locked idle deadline before a workflow renews or revokes the session. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<Long> lockOwnedSessionExpiry(UUID userId, String sessionId) {
		return this.repository.lock(sessionId) ? this.repository.ownedSessionExpiry(sessionId, userId) : Optional.empty();
	}

	boolean isWithinSessionDeadline(long authenticatedAt, long idleExpiry) {
		return withinAbsoluteLifetime(authenticatedAt) && this.repository.isBeforeExpiry(idleExpiry);
	}

	/** The caller holds the subject and catalog locks; supplied facts must exactly match authoritative storage. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<AuthorizationSession> lockForAuthorization(UUID userId, String sessionId, long authenticatedAt, long credentialVersion) {
		if (sessionId == null || !sessionId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
				|| credentialVersion < 1 || !withinAbsoluteLifetime(authenticatedAt) || !this.repository.lock(sessionId)) { return Optional.empty(); }
		var stored = this.repository.authorizationSession(sessionId, userId);
		if (stored.isEmpty()) { return Optional.empty(); }
		var current = stored.orElseThrow();
		// Compare known primitive encodings; do not deserialize arbitrary session objects into protocol state.
		if (!Arrays.equals(current.authenticatedAt(), SerializationUtils.serialize(authenticatedAt))
				|| !Arrays.equals(current.credentialVersion(), SerializationUtils.serialize(credentialVersion))
				|| !isWithinSessionDeadline(authenticatedAt, current.idleExpiry())) { return Optional.empty(); }
		return Optional.of(new AuthorizationSession(current.id(), Instant.ofEpochMilli(authenticatedAt),
				Instant.ofEpochMilli(current.idleExpiry()), Instant.ofEpochMilli(authenticatedAt).plus(this.absoluteTimeout)));
	}

	record AuthorizationSession(UUID id, Instant authenticatedAt, Instant idleExpiresAt, Instant absoluteExpiresAt) {
		@Override
		public String toString() { return "AuthorizationSession[REDACTED]"; }
	}

	@Transactional(propagation = Propagation.MANDATORY)
	void revokeAll(UUID userId, SecurityAuditContext audit) {
		this.repository.deleteAllForUser(userId);
		this.audits.recordSuccess(Action.BROWSER_SESSIONS_REVOKED, userId, audit);
	}

	public void save(Session session, Runnable persist, Supplier<Session> readStored, Supplier<Set<String>> changedAttributes) {
		if (Boolean.TRUE.equals(session.getAttribute(PERSISTENCE_FAILED))) {
			throw new IllegalStateException("Browser session persistence already failed");
		}
		try {
			this.saveTransaction.executeWithoutResult(status -> {
				SecurityContext context = session.getAttribute(SECURITY_CONTEXT);
				Authentication authentication = context == null ? null : context.getAuthentication();
				UUID userId = null;
				if (authentication != null) {
					if (!authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof UUID id)) {
						throw new IllegalStateException("Unexpected browser authentication");
					}
					userId = id;
					if (this.users.lockById(id).status() != IdentityUser.Status.ACTIVE) {
						throw new IllegalStateException("Browser identity is unavailable");
					}
					if (!(session.getAttribute(CREDENTIAL_VERSION) instanceof Long version)
							|| !this.users.passwordVersion(id).equals(Optional.of(version))) {
						throw new IllegalStateException("Browser credential version is no longer current");
					}
				}
				boolean login = Boolean.TRUE.equals(session.getAttribute(LOGIN_PENDING));
				boolean mfa = Boolean.TRUE.equals(session.getAttribute(MFA_PENDING));
				String originalId = login || mfa ? session.getAttribute(ORIGINAL_ID) : session.getId();
				if (Boolean.TRUE.equals(session.getAttribute(PERSISTED))) {
					if (originalId == null || !this.repository.lock(originalId)) {
						throw new IllegalStateException("Browser session is no longer available");
					}
					if (!login && !this.repository.userId(originalId).equals(Optional.ofNullable(userId))) {
						throw new IllegalStateException("Browser session identity changed");
					}
				}
				if (userId != null) {
					if (login) {
						session.removeAttribute(IdentityAdministratorSessions.AUTHENTICATION);
						session.removeAttribute(TOTP_ENROLLMENT);
						session.setAttribute(AUTHENTICATED_AT, System.currentTimeMillis());
					}
					if (!withinAbsoluteLifetime(session.getAttribute(AUTHENTICATED_AT))) {
						throw new IllegalStateException("Browser session expired");
					}
					// Persist a minimal, serializable identity; transport details and credentials stay outside the session.
					session.setAttribute(SECURITY_CONTEXT, new SecurityContextImpl(
							UsernamePasswordAuthenticationToken.authenticated(userId, null,
									this.administrators.authorities(userId, session.getAttribute(AUTHENTICATED_AT),
											session.getAttribute(IdentityAdministratorSessions.AUTHENTICATION)))));
				}
				session.removeAttribute(LOGIN_PENDING);
				session.removeAttribute(MFA_PENDING);
				session.removeAttribute(ORIGINAL_ID);
				session.setAttribute(PERSISTED, true);
				Map<String, byte[]> expectedAttributes = new HashMap<>();
				for (String name : changedAttributes.get()) {
					expectedAttributes.put(name, SerializationUtils.serialize(session.getAttribute(name)));
				}
				// Repeated framework commits must write the metadata that this transaction verifies.
				session.setLastAccessedTime(session.getLastAccessedTime());
				persist.run();
				this.repository.requireStored(session.getId(), userId,
						session.getLastAccessedTime().plus(session.getMaxInactiveInterval()).toEpochMilli());
				requireMatching(session, expectedAttributes, readStored.get());
				if (userId != null && !withinAbsoluteLifetime(session.getAttribute(AUTHENTICATED_AT))) {
					throw new IllegalStateException("Browser session expired during persistence");
				}
				if (login) {
					if (userId == null) {
						throw new IllegalStateException("Authenticated browser identity is required");
					}
					UUID correlation = authentication.getDetails() instanceof PasswordAuthenticationResult details
							? details.correlationId() : UUID.randomUUID();
					this.audits.recordSuccess(Action.BROWSER_SESSION_CREATED, userId,
							new SecurityAuditContext("user:" + userId, "browser:login", correlation));
				}
			});
		}
		catch (RuntimeException ex) {
			// A response commit may be retried by the servlet wrapper; never retry a rolled-back mutable JdbcSession.
			session.setAttribute(PERSISTENCE_FAILED, true);
			throw ex;
		}
	}

	private static void requireMatching(Session expected, Map<String, byte[]> expectedAttributes, Session stored) {
		if (stored == null || !expected.getId().equals(stored.getId())
				// Official JDBC storage uses epoch milliseconds.
				|| expected.getCreationTime().toEpochMilli() != stored.getCreationTime().toEpochMilli()
				|| expected.getLastAccessedTime().toEpochMilli() != stored.getLastAccessedTime().toEpochMilli()
				|| !expected.getMaxInactiveInterval().equals(stored.getMaxInactiveInterval())) {
			throw new IllegalStateException("Browser session storage differs from the requested state");
		}
		for (var entry : expectedAttributes.entrySet()) {
			if (!Arrays.equals(entry.getValue(), SerializationUtils.serialize(stored.getAttribute(entry.getKey())))) {
				throw new IllegalStateException("Browser session attribute was not stored");
			}
		}
	}

	public void delete(String id, UUID actor, Runnable remove) {
		this.transaction.executeWithoutResult(status -> {
			Optional<UUID> user = this.repository.userId(id);
			user.ifPresent(this.users::lockById);
			if (!this.repository.lock(id)) {
				return;
			}
			if (!this.repository.userId(id).equals(user)) {
				throw new IllegalStateException("Browser session identity changed");
			}
			remove.run();
			this.repository.requireDeleted(id);
			user.ifPresent(userId -> this.audits.recordSuccess(Action.BROWSER_SESSION_ENDED, userId,
					new SecurityAuditContext(userId.equals(actor) ? "user:" + actor : "system:browser-session",
							userId.equals(actor) ? "browser:logout" : "browser:session", UUID.randomUUID())));
		});
	}

	public void recordEntryThrottle() {
		this.transaction.executeWithoutResult(status -> this.audits.recordFailure(Action.BROWSER_ENTRY_THROTTLED,
				null, new SecurityAuditContext("anonymous", "browser:entry", UUID.randomUUID())));
	}

	boolean withinAbsoluteLifetime(Object authenticatedAt) {
		long now = System.currentTimeMillis();
		return authenticatedAt instanceof Long time && time <= now && time > now - this.absoluteTimeout.toMillis();
	}

}
