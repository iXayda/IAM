package com.ixayda.iam.service;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import java.util.function.BiFunction;

import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.model.IdentityBrowserSessionPage;
import com.ixayda.iam.model.IdentityBrowserSessionSummary;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityBrowserSessionRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;
import org.springframework.util.SerializationUtils;

/** Owner-scoped browser management; removing a browser does not revoke its independent application grants. */
@Service
public class IdentityAccountSessions {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityBrowserSessionRepository repository;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAccountSessions(IdentityUsers users, IdentityBrowserSessions sessions, IdentityBrowserSessionRepository repository,
			SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users; this.sessions = sessions; this.repository = repository; this.audits = audits;
		this.transaction = new TransactionTemplate(manager); this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	public Result<IdentityBrowserSessionPage> list(IdentityBrowserContext context, int pageSize, IdentityBrowserSessionPage.Cursor after, Runnable persistSession) {
		Assert.notNull(context, "Browser context is required");
		if (pageSize < 1 || pageSize > 100 || after != null && !after.userId().equals(context.userId())) { throw new IllegalArgumentException("Invalid browser session page"); }
		return execute(context, persistSession, (source, audit) -> {
			var rows = this.repository.searchForUser(context.userId(), context.sessionId(), SerializationUtils.serialize(context.credentialVersion()), pageSize + 1, after);
			boolean more = rows.size() > pageSize; var selected = more ? rows.subList(0, pageSize) : rows;
			var items = selected.stream().map(this::summary).filter(Objects::nonNull).toList();
			var next = more ? new IdentityBrowserSessionPage.Cursor(context.userId(), selected.getLast().createdAt(), selected.getLast().id()) : null;
			persistSession.run();
			return new Result<>(Outcome.COMPLETED, new IdentityBrowserSessionPage(items, next));
		});
	}

	public Result<Boolean> revoke(IdentityBrowserContext context, UUID id, Runnable persistSession) {
		Assert.notNull(id, "Browser management id is required");
		return execute(context, persistSession, (source, audit) -> {
			if (!this.repository.isOwnedByPrimaryId(id, context.userId()) || !this.repository.lockByPrimaryId(id)
					|| !this.repository.isOwnedByPrimaryId(id, context.userId())) {
				this.audits.recordFailure(Action.BROWSER_SESSION_ACCESS_DENIED, context.userId(), audit); persistSession.run();
				return new Result<>(Outcome.NOT_FOUND, null);
			}
			// Save while the source exists; a current-session removal then deletes exactly that committed object.
			persistSession.run(); this.repository.deleteOwnedByPrimaryId(id, context.userId());
			this.audits.recordTargetSuccess(Action.BROWSER_SESSION_REVOKED, context.userId(), new SecurityAuditTarget(SecurityAuditTarget.Type.BROWSER_SESSION, id), audit);
			return new Result<>(Outcome.COMPLETED, source.id().equals(id));
		});
	}

	private <T> Result<T> execute(IdentityBrowserContext context, Runnable persistSession,
			BiFunction<IdentityBrowserSessions.AuthorizationSession, SecurityAuditContext, Result<T>> work) {
		Assert.notNull(context, "Browser context is required"); Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Account sessions require an independent transaction"); }
		return this.transaction.execute(tx -> {
			if (this.users.lockForStateChange(context.userId()).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()
					|| !this.sessions.isAuthenticationCurrent(context.userId(), context.authenticatedAt(), context.credentialVersion())) { return new Result<>(Outcome.INVALID_SESSION, null); }
			var source = this.sessions.lockForAuthorization(context.userId(), context.sessionId(), context.authenticatedAt(), context.credentialVersion());
			if (source.isEmpty()) { return new Result<>(Outcome.INVALID_SESSION, null); }
			var result = work.apply(source.orElseThrow(), new SecurityAuditContext("user:" + context.userId(), "browser:account-sessions", context.correlationId()));
			if (!this.sessions.isWithinSessionDeadline(context.authenticatedAt(), source.orElseThrow().idleExpiresAt().toEpochMilli())
					|| !this.sessions.isAuthenticationCurrent(context.userId(), context.authenticatedAt(), context.credentialVersion())) {
				throw new IllegalStateException("Browser authentication expired during session management");
			}
			return result;
		});
	}

	private IdentityBrowserSessionSummary summary(IdentityBrowserSessionRepository.Listing stored) {
		// Accept exactly a known JDK Long encoding; never deserialize an arbitrary session attribute object.
		byte[] bytes = stored.authenticatedAt(); byte[] template = SerializationUtils.serialize(0L);
		if (bytes == null || bytes.length != template.length) { throw new IllegalStateException("Session authentication time is invalid"); }
		long time = ByteBuffer.wrap(bytes, bytes.length - Long.BYTES, Long.BYTES).getLong();
		if (!Arrays.equals(bytes, SerializationUtils.serialize(time))) { throw new IllegalStateException("Session authentication time is invalid"); }
		if (!this.sessions.isWithinSessionDeadline(time, stored.idleExpiry())) { return null; }
		Instant authenticated = Instant.ofEpochMilli(time);
		return new IdentityBrowserSessionSummary(stored.id(), stored.createdAt(), authenticated, stored.lastAccessedAt(),
				Instant.ofEpochMilli(stored.idleExpiry()), authenticated.plus(this.sessions.absoluteTimeout()), stored.current());
	}

	public enum Outcome { COMPLETED, INVALID_SESSION, NOT_FOUND }
	public record Result<T>(Outcome outcome, T value) { }
}
