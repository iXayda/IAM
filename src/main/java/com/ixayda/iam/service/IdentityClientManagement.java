package com.ixayda.iam.service;

import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.function.Function;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;

/** Commits current administrator evidence, a fresh TOTP, client change, session and audit together. */
@Service
public class IdentityClientManagement {

	private final IdentityClients clients;
	private final IdentityAdministratorOperations operations;

	IdentityClientManagement(IdentityClients clients, IdentityAdministratorOperations operations) {
		this.clients = clients;
		this.operations = operations;
	}

	public Result create(IdentityAdministratorContext context, IdentityClientConfiguration configuration, String code, Runnable persistSession) {
		IdentityClientConfiguration config;
		try { config = IdentityClients.normalize(configuration); }
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> {
			var created = this.clients.create(config, audit);
			return new Value(created.client(), created.secret());
		});
	}

	public Result updateConfiguration(IdentityAdministratorContext context, UUID id, long expectedVersion,
			IdentityClientConfiguration configuration, String code, Runnable persistSession) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		IdentityClientConfiguration config;
		try { config = IdentityClients.normalize(configuration); }
		catch (IllegalArgumentException ex) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> new Value(this.clients.updateConfiguration(id, expectedVersion, config, audit), null));
	}

	public Result setEnabled(IdentityAdministratorContext context, UUID id, long expectedVersion, boolean enabled, String code, Runnable persistSession) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> new Value(this.clients.setEnabled(id, expectedVersion, enabled, audit), null));
	}

	public Result rotateSecret(IdentityAdministratorContext context, UUID id, long expectedVersion, String code, Runnable persistSession) {
		if (id == null || expectedVersion < 1) { return rejected(Status.INVALID_INPUT); }
		return execute(context, code, persistSession, audit -> {
			var rotated = this.clients.rotateSecret(id, expectedVersion, audit);
			return new Value(rotated.client(), rotated.secret());
		});
	}

	private Result execute(IdentityAdministratorContext context, String code, Runnable persistSession, Function<SecurityAuditContext, Value> operation) {
		try {
			var result = this.operations.execute(context, code, persistSession, audit -> {
				try { return operation.apply(audit); }
				catch (NoSuchElementException ex) { throw new ChangeRejected(Status.NOT_FOUND); }
				catch (OptimisticLockingFailureException | IdentityClients.ClientConfigurationNotAllowedException ex) { throw new ChangeRejected(Status.CONFLICT); }
			});
			var status = switch (result.status()) {
				case COMPLETED -> Status.COMPLETED;
				case INVALID_SESSION -> Status.INVALID_SESSION;
				case FORBIDDEN -> Status.FORBIDDEN;
				case REJECTED -> Status.REJECTED;
				case THROTTLED -> Status.THROTTLED;
			};
			return result.value() == null ? rejected(status) : new Result(status, result.value().client(), result.value().secret());
		}
		catch (ChangeRejected ex) { return rejected(ex.status); }
	}

	private static Result rejected(Status status) { return new Result(status, null, null); }
	public enum Status { COMPLETED, INVALID_INPUT, INVALID_SESSION, FORBIDDEN, REJECTED, THROTTLED, CONFLICT, NOT_FOUND }
	public record Result(Status status, IdentityClient client, String secret) {
		@Override
		public String toString() { return "IdentityClientManagement.Result[status=" + status + ", REDACTED]"; }
	}
	private record Value(IdentityClient client, String secret) {
		@Override
		public String toString() { return "IdentityClientManagement.Value[REDACTED]"; }
	}
	private static final class ChangeRejected extends RuntimeException {
		private final Status status;
		ChangeRejected(Status status) { this.status = status; }
	}

}
