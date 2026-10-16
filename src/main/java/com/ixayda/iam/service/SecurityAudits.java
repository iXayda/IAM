package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent;
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

	/** Appends success only within the transaction that performs the business operation. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void recordSuccess(SecurityAuditEvent.Action action, UUID targetUserId, SecurityAuditContext context) {
		if (action == null || action.isFailure()) {
			throw new IllegalArgumentException("A success action is required");
		}
		this.repository.append(new SecurityAuditEvent(UUID.randomUUID(), action, targetUserId, context));
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
