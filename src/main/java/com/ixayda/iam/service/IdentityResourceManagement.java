package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.SecurityAuditContext;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/** Consumes operation TOTP and commits the authorized resource change, session and audit together. */
@Service
public class IdentityResourceManagement {

	private final IdentityResources resources;
	private final IdentityAdministratorOperations operations;

	IdentityResourceManagement(IdentityResources resources, IdentityAdministratorOperations operations) {
		this.resources = resources;
		this.operations = operations;
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
		var result = this.operations.execute(context, code, persistSession, operation);
		var status = switch (result.status()) {
			case COMPLETED -> Status.COMPLETED;
			case INVALID_SESSION -> Status.INVALID_SESSION;
			case FORBIDDEN -> Status.FORBIDDEN;
			case REJECTED -> Status.REJECTED;
			case THROTTLED -> Status.THROTTLED;
		};
		return new Result(status, result.value());
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
