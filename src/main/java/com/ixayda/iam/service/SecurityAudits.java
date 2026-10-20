package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent;
import com.ixayda.iam.model.SecurityAuditFilter;
import com.ixayda.iam.model.SecurityAuditPage;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.SecurityAuditRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurityAudits {

	private final SecurityAuditRepository repository;

	SecurityAudits(SecurityAuditRepository repository) {
		this.repository = repository;
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
		this.repository.append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context));
	}

	/** Object changes retain a typed target alongside the operation's trusted attribution. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordTargetSuccess(SecurityAuditEvent.Action action, SecurityAuditTarget target, SecurityAuditContext context) {
		recordTargetSuccess(action, null, target, context);
	}

	/** Role assignments retain both the affected user and the business role. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordTargetSuccess(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditTarget target, SecurityAuditContext context) {
		if (action == null || action.isFailure() || target == null) {
			throw new IllegalArgumentException("A success action and object target are required");
		}
		this.repository.append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context, target));
	}

	/** Failure belongs to a transaction that commits a rejected decision, not to a rolled-back success. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordFailure(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditContext context) {
		if (action == null || !action.isFailure()) {
			throw new IllegalArgumentException("A failure action is required");
		}
		this.repository.append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context));
	}

}
