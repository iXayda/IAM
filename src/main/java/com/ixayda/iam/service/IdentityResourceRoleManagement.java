package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.SecurityAuditContext;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/** Consumes operation TOTP and commits the authorized resource role change, session and audit together. */
@Service
public class IdentityResourceRoleManagement {

	private final IdentityResourceRoles roles;
	private final IdentityAdministratorOperations operations;

	IdentityResourceRoleManagement(IdentityResourceRoles roles, IdentityAdministratorOperations operations) {
		this.roles = roles;
		this.operations = operations;
	}

	public Result create(IdentityAdministratorContext context, UUID resourceId, String roleCode, String displayName, String code, Runnable persistSession) {
		if (resourceId == null) { return rejected(Status.INVALID_INPUT); }
		String exactCode;
		String normalized;
		try {
			exactCode = IdentityResourceRoles.requireCode(roleCode);
			normalized = IdentityResourceRoles.normalizeDisplayName(displayName);
		}
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		try {
			return execute(context, code, persistSession, audit -> {
				try { return this.roles.create(resourceId, exactCode, normalized, audit); }
				catch (DuplicateKeyException ex) { throw new RoleCodeConflict(ex); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (IdentityResourceRoles.ResourceInactiveException ex) { throw new ChangeRejected(Status.CONFLICT); }
			});
		}
		catch (RoleCodeConflict ex) {
			if (this.roles.findByCode(resourceId, exactCode).isPresent()) { return rejected(Status.CONFLICT); }
			throw (DuplicateKeyException) ex.getCause();
		}
		catch (ChangeRejected ex) { return rejected(ex.status); }
	}

	public Result updateDisplayName(IdentityAdministratorContext context, UUID id, long expectedVersion,
			String displayName, String code, Runnable persistSession) {
		String normalized;
		try { normalized = IdentityResourceRoles.normalizeDisplayName(displayName); }
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		return change(context, id, expectedVersion, code, persistSession,
				audit -> this.roles.updateDisplayName(id, expectedVersion, normalized, audit));
	}

	public Result setEnabled(IdentityAdministratorContext context, UUID id, long expectedVersion,
			boolean enabled, String code, Runnable persistSession) {
		return change(context, id, expectedVersion, code, persistSession,
				audit -> this.roles.setEnabled(id, expectedVersion, enabled, audit));
	}

	private Result change(IdentityAdministratorContext context, UUID id, long expectedVersion, String code,
			Runnable persistSession, Function<SecurityAuditContext, IdentityResourceRole> operation) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		try {
			return execute(context, code, persistSession, audit -> {
				try { return operation.apply(audit); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (OptimisticLockingFailureException ex) { throw new ChangeRejected(Status.CONFLICT); }
				catch (IdentityResourceRoles.ResourceInactiveException ex) { throw new ChangeRejected(Status.CONFLICT); }
			});
		}
		catch (ChangeRejected ex) { return rejected(ex.status); }
	}

	private Result execute(IdentityAdministratorContext context, String code, Runnable persistSession,
			Function<SecurityAuditContext, IdentityResourceRole> operation) {
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
	public record Result(Status status, IdentityResourceRole role) { }

	private static final class RoleCodeConflict extends RuntimeException {
		RoleCodeConflict(DuplicateKeyException cause) { super(cause); }
	}
	private static final class ChangeRejected extends RuntimeException {
		private final Status status;
		ChangeRejected(Status status) { this.status = status; }
	}
}
