package com.ixayda.iam.session.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.session.UserSessionNotFoundException;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
@Transactional(readOnly = true)
class DefaultSessionOperations implements SessionOperations {

	private final JdbcUserSessionRepository repository;

	private final TenantOperations tenants;

	private final UserOperations users;

	private final SessionTimeSource timeSource;

	DefaultSessionOperations(JdbcUserSessionRepository repository, TenantOperations tenants, UserOperations users,
			SessionTimeSource timeSource) {
		this.repository = repository;
		this.tenants = tenants;
		this.users = users;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public UserSession start(TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod, SessionAbsoluteTtl absoluteTtl) {
		return startSession(tenantId, userId, authenticationMethod, null, absoluteTtl);
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY)
	public UserSession start(TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod,
			Set<SessionAuthenticationFactor> authenticationFactors, SessionAbsoluteTtl absoluteTtl) {
		Objects.requireNonNull(authenticationFactors, "Session authentication factors must not be null");
		return startSession(tenantId, userId, authenticationMethod, authenticationFactors, absoluteTtl);
	}

	private UserSession startSession(TenantId tenantId, UserId userId,
			SessionAuthenticationMethod authenticationMethod,
			Set<SessionAuthenticationFactor> authenticationFactors, SessionAbsoluteTtl absoluteTtl) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(authenticationMethod, "Session authentication method must not be null");
		Objects.requireNonNull(absoluteTtl, "Session absolute TTL must not be null");
		requireWriteTransaction();

		Tenant tenant = this.tenants.requireActiveForWrite(tenantId);
		User user = this.users.requireActiveForWrite(tenantId, userId);
		if (!tenant.id().equals(tenantId) || !user.tenantId().equals(tenantId) || !user.id().equals(userId)) {
			throw new IllegalStateException("Session lifecycle guards returned a different tenant or user");
		}
		Instant authenticatedAt = this.timeSource.now();
		Set<SessionAuthenticationFactor> factors = authenticationFactors == null
				? Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, authenticatedAt))
				: authenticationFactors;
		UserSession session = UserSession.start(SessionId.random(), tenantId, userId, authenticationMethod,
				factors, tenant.version(), user.securityVersion(), authenticatedAt,
				absoluteTtl.expiresAt(authenticatedAt));
		return this.repository.insert(session);
	}

	@Override
	public Optional<UserSession> findById(TenantId tenantId, SessionId sessionId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(sessionId, "Session ID must not be null");
		return this.repository.findById(tenantId, sessionId);
	}

	@Override
	public Optional<UserSession> findUsable(TenantId tenantId, SessionId sessionId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(sessionId, "Session ID must not be null");
		Optional<UserSession> stored = this.repository.findById(tenantId, sessionId);
		if (stored.isEmpty()) {
			return Optional.empty();
		}
		UserSession session = stored.orElseThrow();
		if (session.isRevoked() || session.isExpiredAt(this.timeSource.now())) {
			return Optional.empty();
		}

		Optional<Tenant> tenant = this.tenants.findById(tenantId);
		Tenant currentTenant = tenant.orElse(null);
		if (currentTenant == null || !currentTenant.isActive()
				|| currentTenant.version() != session.issuedTenantVersion()) {
			return Optional.empty();
		}
		Optional<User> user = this.users.findById(tenantId, session.userId());
		User currentUser = user.orElse(null);
		if (currentUser == null || !currentUser.isActive()
				|| currentUser.securityVersion() != session.issuedUserVersion()) {
			return Optional.empty();
		}
		return Optional.of(session);
	}

	@Override
	@Transactional
	public UserSession revoke(TenantId tenantId, SessionId sessionId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(sessionId, "Session ID must not be null");
		UserSession current = requireSession(tenantId, sessionId);
		if (current.isRevoked()) {
			return current;
		}
		UserSession changed = current.revoke(this.timeSource.now());
		try {
			return this.repository.update(current, changed);
		}
		catch (UserSessionConcurrentUpdateException ex) {
			UserSession latest = requireSession(tenantId, sessionId);
			if (latest.isRevoked()) {
				return latest;
			}
			throw ex;
		}
	}

	private UserSession requireSession(TenantId tenantId, SessionId sessionId) {
		return this.repository.findById(tenantId, sessionId)
			.orElseThrow(() -> new UserSessionNotFoundException(tenantId, sessionId));
	}

	private static void requireWriteTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.isCurrentTransactionReadOnly()) {
			throw new IllegalTransactionStateException("Starting a session requires an existing read-write transaction");
		}
	}

}
