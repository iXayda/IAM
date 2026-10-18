package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.UUID;

import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministrators;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Explicit local deployment command; credentials are read without echo and never accepted as arguments. */
public final class AdministratorBootstrapCommand {

	private AdministratorBootstrapCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1) { throw new IllegalArgumentException("bootstrap-admin accepts no command arguments"); }
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Administrator initialization requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE)
				.initializers(candidate -> {
					if (candidate instanceof WebApplicationContext) {
						throw new IllegalStateException("Administrator initialization requires a non-Web application");
					}
				}).run()) {
			execute(console, context.getBean(IdentityAdministrators.class));
		}
	}

	static void execute(Console console, IdentityAdministrators administrators) {
		UUID correlationId = UUID.randomUUID();
		UUID userId;
		MfaRecoveryCodeSet recoveryCodes;
		char[] password = null;
		char[] confirmation = null;
		char[] code = null;
		try {
			var authentication = new TotpAuthenticationContext("deployment:admin-bootstrap", InetAddress.getLoopbackAddress(), correlationId);
			var candidate = administrators.candidateId();
			String selection = candidate.map(UUID::toString).orElseGet(() -> console.readLine("User UUID (or new): "));
			if ("new".equals(selection)) {
				String username = console.readLine("Username: ");
				String displayName = console.readLine("Display name: ");
				password = console.readPassword("New password: ");
				confirmation = console.readPassword("Confirm password: ");
				if (password == null || confirmation == null || !Arrays.equals(password, confirmation)) {
					throw new IllegalStateException("Password confirmation failed");
				}
				userId = administrators.createCandidate(username, displayName, new String(password),
						new SecurityAuditContext("deployment:operator", authentication.source(), correlationId));
				console.printf("Candidate user: %s%n", userId);
				checkOutput(console);
			}
			else {
				userId = UUID.fromString(selection);
				if (candidate.isPresent()) {
					console.printf("Resuming candidate: %s%n", userId);
					checkOutput(console);
				}
				password = console.readPassword("Current password: ");
			}
			if (password == null) { throw new IllegalStateException("Input cancelled"); }
			var preparation = administrators.prepareCandidate(userId, new String(password), authentication).orElseThrow(
					() -> new IllegalStateException("Candidate preparation was rejected"));
			if (preparation.enrollment().isPresent()) {
				var enrollment = preparation.enrollment().orElseThrow();
				console.printf("TOTP secret (add to authenticator): %s%nExpires at: %s%n", enrollment.secret(), enrollment.expiresAt());
				checkOutput(console);
			}
			code = console.readPassword("Current TOTP code: ");
			if (code == null) { throw new IllegalStateException("Input cancelled"); }
			var result = administrators.bootstrap(userId, preparation.enrollment().map(value -> value.factorId()).orElse(null),
					new String(password), new String(code), authentication);
			if (result.isEmpty()) {
				throw new IllegalStateException("Initialization was rejected");
			}
			recoveryCodes = result.orElseThrow();
		}
		catch (RuntimeException | IOError ex) {
			// Storage and terminal errors may contain private details. Expose only the audit correlation.
			throw new IllegalStateException("Administrator initialization was not confirmed; correlation: " + correlationId);
		}
		finally {
			if (password != null) { Arrays.fill(password, '\0'); }
			if (confirmation != null) { Arrays.fill(confirmation, '\0'); }
			if (code != null) { Arrays.fill(code, '\0'); }
		}
		try {
			console.printf("Administrator initialized: %s%nRecovery codes (store securely):%n", userId);
			for (String recoveryCode : recoveryCodes.codes()) { console.printf("%s%n", recoveryCode); }
			console.printf("Correlation: %s%n", correlationId);
			checkOutput(console);
		}
		catch (RuntimeException ex) {
			throw new IllegalStateException("Administrator initialized; recovery code delivery was not confirmed; correlation: " + correlationId);
		}
	}

	private static void checkOutput(Console console) {
		// PrintWriter suppresses I/O exceptions; checkError also flushes pending output.
		if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); }
	}

}
