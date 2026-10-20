package com.ixayda.iam.service;

import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorContext;

import org.springframework.stereotype.Service;

/** A current administrator and fresh operation TOTP may terminate all authentication for one user. */
@Service
public class IdentityUserSessionManagement {

	private final IdentityUsers users;
	private final IdentitySessionRevocations revocations;
	private final IdentityAdministratorOperations operations;

	IdentityUserSessionManagement(IdentityUsers users, IdentitySessionRevocations revocations, IdentityAdministratorOperations operations) {
		this.users = users; this.revocations = revocations; this.operations = operations;
	}

	public Result revokeAll(IdentityAdministratorContext context, UUID userId, String code, Runnable persistSession) {
		if (userId == null) { throw new IllegalArgumentException("Target user is required"); }
		try {
			var result = this.operations.executeRevokingSessions(context, userId, code, persistSession, audit -> {
				if (this.users.findById(userId).isEmpty()) { throw new TargetNotFound(); }
				this.revocations.revokeForUser(userId, audit);
				return context.actorId().equals(userId);
			});
			var status = switch (result.status()) {
				case COMPLETED -> Status.COMPLETED;
				case INVALID_SESSION -> Status.INVALID_SESSION;
				case FORBIDDEN -> Status.FORBIDDEN;
				case REJECTED -> Status.REJECTED;
				case THROTTLED -> Status.THROTTLED;
			};
			return new Result(status, Boolean.TRUE.equals(result.value()));
		}
		catch (TargetNotFound ex) { return new Result(Status.NOT_FOUND, false); }
	}

	public enum Status { COMPLETED, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, NOT_FOUND }
	public record Result(Status status, boolean currentSessionRevoked) { }
	private static final class TargetNotFound extends RuntimeException { }
}
