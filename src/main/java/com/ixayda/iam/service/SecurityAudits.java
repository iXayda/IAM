package com.ixayda.iam.service;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditPage;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.SecurityAuditRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class SecurityAudits {

	private final SecurityAuditRepository repository;
	// Low bit marks a known outage; the generation prevents an older commit clearing a newer failure.
	private final AtomicLong availability = new AtomicLong();

	SecurityAudits(SecurityAuditRepository repository) {
		this.repository = repository;
	}

	/** Read-only probe: a known write failure clears only after a real audit transaction commits. */
	public boolean isAvailable() {
		return (this.availability.get() & 1L) == 0 && this.repository.canAppend();
	}

	/** Internal query; the caller authorizes access and retains the returned cursor's filters. */
	public SecurityAuditPage search(SecurityAuditFilter filter, int pageSize, SecurityAuditPage.Cursor after) {
		if (filter == null) {
			throw new IllegalArgumentException("Audit filter is required");
		}
		if (pageSize < 1 || pageSize > 100) {
			throw new IllegalArgumentException("Page size must be between 1 and 100");
		}
		if (after != null && !after.filter().equals(filter)) {
			throw new IllegalArgumentException("Cursor audit filters do not match");
		}
		var rows = this.repository.search(filter, pageSize + 1, after);
		boolean hasMore = rows.size() > pageSize;
		var items = hasMore ? rows.subList(0, pageSize) : rows;
		SecurityAuditPage.Cursor next = null;
		if (hasMore) {
			var last = items.getLast();
			next = new SecurityAuditPage.Cursor(last.recordedAt(), last.id(), filter);
		}
		return new SecurityAuditPage(items, next);
	}

	/** Appends success only within the transaction that performs the business operation. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordSuccess(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditContext context) {
		if (action == null || action.isFailure()) {
			throw new IllegalArgumentException("A success action is required");
		}
		append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context));
	}

	/** Object changes retain a typed target alongside the operation's trusted attribution. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordTargetSuccess(SecurityAuditEvent.Action action, SecurityAuditTarget target, SecurityAuditContext context) {
		recordTargetSuccess(action, null, target, context);
	}

	/** User-bound object changes retain both the affected user and their typed target. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordTargetSuccess(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditTarget target, SecurityAuditContext context) {
		if (action == null || action.isFailure() || target == null) {
			throw new IllegalArgumentException("A success action and object target are required");
		}
		append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context, target));
	}

	/** Failure belongs to a transaction that commits a rejected decision, not to a rolled-back success. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordFailure(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditContext context) {
		if (action == null || !action.isFailure()) {
			throw new IllegalArgumentException("A failure action is required");
		}
		append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context));
	}

	private void append(SecurityAuditEvent event) {
		long observed = this.availability.get();
		try { this.repository.append(event); }
		catch (RuntimeException ex) { markUnavailable(); throw ex; }
		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
			@Override
			public void afterCommit() { availability.compareAndSet(observed, observed & ~1L); }
			@Override
			public void afterCompletion(int status) { if (status == STATUS_UNKNOWN) { markUnavailable(); } }
		});
	}

	private void markUnavailable() { this.availability.updateAndGet(state -> (state + 2) | 1L); }

}
