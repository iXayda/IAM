package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Consumes operation TOTP and commits the authorized resource change, session and audit together. */
@Service
public class IdentityResourceManagement {

	private final IdentityResources resources;
	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAdministratorSessions administrators;
	private final IdentityTotps totps;
	private final TotpAuthenticationLimits limits;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityResourceManagement(IdentityResources resources, IdentityUsers users, IdentityBrowserSessions sessions,
			IdentityAdministratorSessions administrators, IdentityTotps totps, TotpAuthenticationLimits limits,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.resources = resources;
		this.users = users;
		this.sessions = sessions;
		this.administrators = administrators;
		this.totps = totps;
		this.limits = limits;
		this.audits = audits;
		this.transaction = new TransactionTemplate(manager);
	}

	public Result create(IdentityAdministratorContext context, String audience, String displayName, String code, Runnable persistSession) {
		String exactAudience;
		String normalized;
		try {
			exactAudience = IdentityResources.requireAudience(audience);
			normalized = IdentityResources.normalizeDisplayName(displayName);
		}
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		try {
			return execute(context, code, persistSession, audit -> {
				try { return this.resources.create(exactAudience, normalized, audit); }
				catch (DuplicateKeyException ex) { throw new AudienceConflict(ex); }
			});
		}
		catch (AudienceConflict ex) {
			if (this.resources.findByAudience(exactAudience).isPresent()) { return rejected(Status.CONFLICT); }
			throw (DuplicateKeyException) ex.getCause();
		}
	}

	public Result updateDisplayName(IdentityAdministratorContext context, UUID id, long expectedVersion,
			String displayName, String code, Runnable persistSession) {
		String normalized;
		try { normalized = IdentityResources.normalizeDisplayName(displayName); }
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		return change(context, id, expectedVersion, code, persistSession,
				audit -> this.resources.updateDisplayName(id, expectedVersion, normalized, audit));
	}

	public Result setEnabled(IdentityAdministratorContext context, UUID id, long expectedVersion,
			boolean enabled, String code, Runnable persistSession) {
		return change(context, id, expectedVersion, code, persistSession,
				audit -> this.resources.setEnabled(id, expectedVersion, enabled, audit));
	}

	private Result change(IdentityAdministratorContext context, UUID id, long expectedVersion, String code,
			Runnable persistSession, Function<SecurityAuditContext, IdentityResource> operation) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		try {
			return execute(context, code, persistSession, audit -> {
				try { return operation.apply(audit); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (OptimisticLockingFailureException ex) { throw new ChangeRejected(Status.CONFLICT); }
			});
		}
		catch (ChangeRejected ex) { return rejected(ex.status); }
	}

	private Result execute(IdentityAdministratorContext context, String code, Runnable persistSession,
			Function<SecurityAuditContext, IdentityResource> operation) {
		Assert.notNull(context, "Administrator context is required");
		Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalStateException("Administrator resource management requires an independent transaction");
		}
		return this.transaction.execute(status -> {
			var attribution = context.authentication();
			var attempt = this.limits.lock(context.actorId(), attribution);
			if (!attempt.allowed()) {
				this.audits.recordFailure(Action.TOTP_AUTH_THROTTLED, null,
						new SecurityAuditContext("anonymous", attribution.source(), attribution.correlationId()));
				return rejected(Status.THROTTLED);
			}
			if (this.users.lockForTotp(context.actorId()).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()) {
				return rejected(Status.INVALID_SESSION);
			}
			var expiry = this.sessions.lockOwnedSessionExpiry(context.actorId(), context.sessionId());
			if (expiry.isEmpty()
					|| !this.sessions.isAuthenticationCurrent(context.actorId(), context.authenticatedAt(), context.credentialVersion())) {
				return rejected(Status.INVALID_SESSION);
			}
			var audit = new SecurityAuditContext("user:" + context.actorId(), attribution.source(), attribution.correlationId());
			if (this.administrators.authorities(context.actorId(), context.authenticatedAt(), context.management()).isEmpty()) {
				this.audits.recordFailure(Action.ADMIN_ACCESS_DENIED, context.actorId(), audit);
				return rejected(Status.FORBIDDEN);
			}
			var verified = this.totps.verifyInTransaction(context.actorId(), code, attribution);
			if (verified.isEmpty()) { return rejected(Status.REJECTED); }
			if (verified.orElseThrow().credentialVersion() != context.credentialVersion()) {
				throw new IllegalStateException("Password authentication is no longer current");
			}
			var result = operation.apply(audit);
			persistSession.run();
			if (!this.sessions.isAuthenticationCurrent(context.actorId(), context.authenticatedAt(), context.credentialVersion())
					|| this.administrators.authorities(context.actorId(), context.authenticatedAt(), context.management()).isEmpty()
					|| !this.sessions.isWithinSessionDeadline(context.authenticatedAt(), expiry.orElseThrow())) {
				throw new IllegalStateException("Administrator authentication is no longer current");
			}
			return new Result(Status.COMPLETED, result);
		});
	}

	private static Result rejected(Status status) { return new Result(status, null); }
	public enum Status { COMPLETED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, CONFLICT, NOT_FOUND }
	public record Result(Status status, IdentityResource resource) { }

	private static final class AudienceConflict extends RuntimeException {
		AudienceConflict(DuplicateKeyException cause) { super(cause); }
	}
	private static final class ChangeRejected extends RuntimeException {
		private final Status status;
		ChangeRejected(Status status) { this.status = status; }
	}
}
