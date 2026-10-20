package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorContext;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/** Authorizes direct assignments and commits operation TOTP, binding, session and audit together. */
@Service
public class IdentityUserRoleManagement {

	private final IdentityUserRoles bindings;
	private final IdentityAdministratorOperations operations;

	IdentityUserRoleManagement(IdentityUserRoles bindings, IdentityAdministratorOperations operations) {
		this.bindings = bindings;
		this.operations = operations;
	}

	public Result change(IdentityAdministratorContext context, UUID userId, UUID roleId, long expectedVersion,
			boolean grant, String code, Runnable persistSession) {
		if (userId == null || roleId == null || expectedVersion < 0) { return new Result(Status.INVALID_INPUT, null); }
		try {
			var result = this.operations.execute(context, userId, code, persistSession, audit -> {
				try { return this.bindings.change(userId, roleId, expectedVersion, grant, audit); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (OptimisticLockingFailureException | IdentityUserRoles.BindingNotAllowedException ex) {
					throw new ChangeRejected(Status.CONFLICT);
				}
			});
			var status = switch (result.status()) {
				case COMPLETED -> Status.COMPLETED;
				case INVALID_SESSION -> Status.INVALID_SESSION;
				case FORBIDDEN -> Status.FORBIDDEN;
				case REJECTED -> Status.REJECTED;
				case THROTTLED -> Status.THROTTLED;
			};
			return new Result(status, result.value());
		}
		catch (ChangeRejected ex) { return new Result(ex.status, null); }
	}

	public enum Status { COMPLETED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, CONFLICT, NOT_FOUND }
	public record Result(Status status, IdentityUserRoles.ChangeResult change) { }

	private static final class ChangeRejected extends RuntimeException {
		private final Status status;
		ChangeRejected(Status status) { this.status = status; }
	}

}
