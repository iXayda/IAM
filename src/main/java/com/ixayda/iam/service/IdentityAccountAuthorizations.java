package com.ixayda.iam.service;

import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAuthorizationPage;
import com.ixayda.iam.model.IdentityAuthorizationSummary;
import com.ixayda.iam.model.IdentityAuthorizationSummary.Status;
import com.ixayda.iam.model.IdentityBrowserContext;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.repository.IdentityAuthorizationBindingRepository;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.Assert;

/** Current owners manage independent application grants without ending their IAM browser login. */
@Service
public class IdentityAccountAuthorizations {

	private final IdentityUsers users;
	private final IdentityBrowserSessions sessions;
	private final IdentityAuthorizationBindingRepository repository;
	private final IdentityAuthorizationBindings bindings;
	private final IdentityAuthorizations authorizations;
	private final IdentityRefreshTokens refresh;
	private final IdentityAuthorizationRevocations revocations;
	private final SecurityAudits audits;
	private final TransactionTemplate transaction;

	IdentityAccountAuthorizations(IdentityUsers users, IdentityBrowserSessions sessions, IdentityAuthorizationBindingRepository repository,
			IdentityAuthorizationBindings bindings, IdentityAuthorizations authorizations, IdentityRefreshTokens refresh,
			IdentityAuthorizationRevocations revocations, SecurityAudits audits, PlatformTransactionManager manager) {
		this.users = users; this.sessions = sessions; this.repository = repository; this.bindings = bindings;
		this.authorizations = authorizations; this.refresh = refresh; this.revocations = revocations; this.audits = audits;
		this.transaction = new TransactionTemplate(manager); this.transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
	}

	public Result<IdentityAuthorizationPage> list(IdentityBrowserContext context, int pageSize, IdentityAuthorizationPage.Cursor after, Runnable persistSession) {
		Assert.notNull(context, "Browser context is required");
		if (pageSize < 1 || pageSize > 100 || after != null && !after.userId().equals(context.userId())) { throw new IllegalArgumentException("Invalid authorization page"); }
		return execute(context, persistSession, audit -> {
			var rows = this.repository.searchForUser(context.userId(), pageSize + 1, after);
			boolean more = rows.size() > pageSize; var selected = more ? rows.subList(0, pageSize) : rows;
			var summaries = new HashMap<UUID, IdentityAuthorizationSummary>();
			// Catalog revocations take native locks in UUID order; preserve that order even when the display is chronological.
			selected.stream().sorted(java.util.Comparator.comparing(row -> row.id().toString())).forEach(row -> {
				var stored = this.authorizations.lockForUse(row.id()).orElseThrow(() -> new IllegalStateException("Listed authorization is missing"));
				summaries.put(row.id(), summary(context.userId(), row, stored));
			});
			var next = more ? new IdentityAuthorizationPage.Cursor(context.userId(), selected.getLast().issuedAt(), selected.getLast().id()) : null;
			return new Result<>(Outcome.COMPLETED, new IdentityAuthorizationPage(selected.stream().map(row -> summaries.get(row.id())).toList(), next));
		});
	}

	public Result<Boolean> revoke(IdentityBrowserContext context, UUID id, Runnable persistSession) {
		Assert.notNull(id, "Authorization id is required");
		return execute(context, persistSession, audit -> {
			// Scope before taking any foreign grant lock; missing and foreign identifiers are indistinguishable.
			if (!this.repository.isOwnedBy(id, context.userId())) {
				this.audits.recordFailure(Action.AUTHORIZATION_ACCESS_DENIED, context.userId(), audit);
				return new Result<>(Outcome.NOT_FOUND, null);
			}
			return new Result<>(Outcome.COMPLETED, this.revocations.revoke(id, audit));
		});
	}

	private <T> Result<T> execute(IdentityBrowserContext context, Runnable persistSession, Function<SecurityAuditContext, Result<T>> work) {
		Assert.notNull(context, "Browser context is required"); Assert.notNull(persistSession, "Session persistence is required");
		if (TransactionSynchronizationManager.isActualTransactionActive()) { throw new IllegalStateException("Account authorizations require an independent transaction"); }
		return this.transaction.execute(tx -> {
			if (this.users.lockForStateChange(context.userId()).filter(user -> user.status() == IdentityUser.Status.ACTIVE).isEmpty()
					|| !this.sessions.isAuthenticationCurrent(context.userId(), context.authenticatedAt(), context.credentialVersion())) { return new Result<>(Outcome.INVALID_SESSION, null); }
			var session = this.sessions.lockForAuthorization(context.userId(), context.sessionId(), context.authenticatedAt(), context.credentialVersion());
			if (session.isEmpty()) { return new Result<>(Outcome.INVALID_SESSION, null); }
			var result = work.apply(new SecurityAuditContext("user:" + context.userId(), "browser:account-authorizations", context.correlationId()));
			persistSession.run();
			if (!this.sessions.isWithinSessionDeadline(context.authenticatedAt(), session.orElseThrow().idleExpiresAt().toEpochMilli())
					|| !this.sessions.isAuthenticationCurrent(context.userId(), context.authenticatedAt(), context.credentialVersion())) {
				throw new IllegalStateException("Browser authentication expired during authorization management");
			}
			return result;
		});
	}

	private IdentityAuthorizationSummary summary(UUID owner, IdentityAuthorizationBindingRepository.Listing row, IdentityAuthorizations.Snapshot stored) {
		var authorization = stored.authorization();
		var original = this.bindings.findByAuthorization(authorization).orElseThrow(() -> new IllegalStateException("Original authorization bounds are missing"));
		if (!owner.equals(original.session().access().userId()) || !original.id().equals(row.id()) || !original.issuedAt().equals(row.issuedAt())) {
			throw new IllegalStateException("Authorization listing does not match its owner and original bounds");
		}
		var family = this.refresh.findByAuthorization(authorization); var access = authorization.getAccessToken(); var code = authorization.getToken(OAuth2AuthorizationCode.class);
		var expiry = family.filter(value -> value.status() == IdentityRefreshFamily.Status.ACTIVE).map(IdentityRefreshFamily::idleExpiresAt)
				.orElseGet(() -> access == null ? original.codeExpiresAt() : access.getToken().getExpiresAt().truncatedTo(ChronoUnit.SECONDS));
		Status status;
		if (IdentityAuthorizations.isRevoked(authorization)) { status = Status.REVOKED; }
		else if (family.filter(value -> value.status() == IdentityRefreshFamily.Status.QUARANTINED).isPresent()) { status = Status.QUARANTINED; }
		else if (!this.bindings.isBeforeDeadline(expiry)) { status = Status.EXPIRED; }
		else if (access == null && code != null && !code.isInvalidated()) { status = Status.PENDING; }
		else if (access != null && !access.isInvalidated()) { status = Status.ACTIVE; }
		else { status = Status.INACTIVE; }
		var scopes = access == null ? original.scopes() : access.getToken().getScopes(); var target = original.session().access();
		return new IdentityAuthorizationSummary(row.id(), target.clientId(), row.clientName(), target.resourceId(), row.resourceName(),
				target.audience(), row.issuedAt(), expiry, scopes, status);
	}

	public enum Outcome { COMPLETED, INVALID_SESSION, NOT_FOUND }
	public record Result<T>(Outcome outcome, T value) { }
}
