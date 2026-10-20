package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResourceCredential;
import com.ixayda.iam.model.SecurityAuditContext;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/** Commits current administrator evidence, operation TOTP, credential change, session and audit together. */
@Service
public class IdentityResourceCredentialManagement {

	private final IdentityResourceCredentials credentials;
	private final IdentityAdministratorOperations operations;

	IdentityResourceCredentialManagement(IdentityResourceCredentials credentials, IdentityAdministratorOperations operations) {
		this.credentials = credentials;
		this.operations = operations;
	}

	public Result rotateSecret(IdentityAdministratorContext context, UUID id, long expectedVersion, String code, Runnable persistSession) {
		if (id == null || expectedVersion < 0) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> {
			var delivered = this.credentials.rotateSecret(id, expectedVersion, audit);
			return new Value(delivered.credential(), delivered.secret());
		});
	}

	public Result disable(IdentityAdministratorContext context, UUID id, long expectedVersion, String code, Runnable persistSession) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> new Value(this.credentials.disable(id, expectedVersion, audit), null));
	}

	private Result execute(IdentityAdministratorContext context, String code, Runnable persistSession, Function<SecurityAuditContext, Value> operation) {
		try {
			var result = this.operations.execute(context, code, persistSession, audit -> {
				try { return operation.apply(audit); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (OptimisticLockingFailureException | IdentityResourceCredentials.ResourceCredentialNotAllowedException ex) { throw new ChangeRejected(Status.CONFLICT); }
			});
			var status = switch (result.status()) {
				case COMPLETED -> Status.COMPLETED;
				case INVALID_SESSION -> Status.INVALID_SESSION;
				case FORBIDDEN -> Status.FORBIDDEN;
				case REJECTED -> Status.REJECTED;
				case THROTTLED -> Status.THROTTLED;
			};
			return result.value() == null ? rejected(status) : new Result(status, result.value().credential(), result.value().secret());
		}
		catch (ChangeRejected ex) { return rejected(ex.status); }
	}

	private static Result rejected(Status status) { return new Result(status, null, null); }
	public enum Status { COMPLETED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, CONFLICT, NOT_FOUND }
	public record Result(Status status, IdentityResourceCredential credential, String secret) {
		@Override
		public String toString() { return "IdentityResourceCredentialManagement.Result[status=" + status + ", REDACTED]"; }
	}
	private record Value(IdentityResourceCredential credential, String secret) {
		@Override
		public String toString() { return "IdentityResourceCredentialManagement.Value[REDACTED]"; }
	}
	private static final class ChangeRejected extends RuntimeException {
		private final Status status;
		ChangeRejected(Status status) { this.status = status; }
	}

}
