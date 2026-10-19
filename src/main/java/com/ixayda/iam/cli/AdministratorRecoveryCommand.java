package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.util.Arrays;
import java.util.UUID;

import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityAdministratorRecoveries;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Authorized offline recovery; the proof remains in-process and secrets never enter argv or environment variables. */
public final class AdministratorRecoveryCommand {

	private AdministratorRecoveryCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !args[0].equals("recover-admin")) {
			throw new IllegalArgumentException("recover-admin accepts no command arguments");
		}
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Administrator recovery requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE)
				.initializers(candidate -> {
					if (candidate instanceof WebApplicationContext) {
						throw new IllegalStateException("Administrator recovery requires a non-Web application");
					}
				}).run()) {
			execute(console, context.getBean(IdentityAdministratorRecoveries.class));
		}
	}

	static void execute(Console console, IdentityAdministratorRecoveries recoveries) {
		UUID correlationId = UUID.randomUUID();
		UUID userId;
		MfaRecoveryCodeSet recoveryCodes;
		char[] password = null;
		char[] code = null;
		try {
			console.printf("Administrator recovery correlation: %s%n", correlationId);
			console.printf("After a confirmed recovery, notify the owner through a previously verified independent channel and record delivery with this correlation.%n");
			checkOutput(console);
			if (!"RECOVER".equals(console.readLine("Service stopped and identity verified (type RECOVER): "))) {
				throw new IllegalStateException("Recovery was not authorized");
			}
			String operator = console.readLine("Deployment operator: ");
			String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
				throw new IllegalArgumentException("Deployment operator and authorization reference are required");
			}
			var audit = new SecurityAuditContext("deployment:" + operator, "deployment:admin-recovery:" + reference, correlationId);
			String selection = console.readLine("Administrator user UUID: ");
			userId = UUID.fromString(selection);
			if (!userId.toString().equalsIgnoreCase(selection)) { throw new IllegalArgumentException("Canonical UUID is required"); }
			password = console.readPassword("Current password: ");
			if (password == null) { throw new IllegalStateException("Input cancelled"); }
			var preparation = recoveries.begin(userId, new String(password), audit)
					.orElseThrow(() -> new IllegalStateException("Recovery preparation was rejected"));
			var enrollment = preparation.enrollment();
			console.printf("TOTP secret (IAM, SHA-1, 6 digits, 30 seconds): %s%nExpires at: %s%n",
					enrollment.secret(), enrollment.expiresAt());
			checkOutput(console);
			code = console.readPassword("New authenticator code: ");
			if (code == null) { throw new IllegalStateException("Input cancelled"); }
			recoveryCodes = recoveries.complete(userId, preparation.recoveryId(), preparation.token(), new String(password), new String(code), audit)
					.orElseThrow(() -> new IllegalStateException("Recovery was rejected"));
		}
		catch (RuntimeException | IOError ex) {
			throw new IllegalStateException("Administrator recovery was not confirmed; correlation: " + correlationId);
		}
		finally {
			if (password != null) { Arrays.fill(password, '\0'); }
			if (code != null) { Arrays.fill(code, '\0'); }
		}
		try {
			console.printf("Administrator recovered: %s%nRecovery codes (store securely):%n", userId);
			for (String recoveryCode : recoveryCodes.codes()) { console.printf("%s%n", recoveryCode); }
			console.printf("Correlation: %s%n", correlationId);
			checkOutput(console);
		}
		catch (RuntimeException | IOError ex) {
			throw new IllegalStateException("Administrator recovered; recovery code delivery was not confirmed; correlation: " + correlationId);
		}
	}

	private static void checkOutput(Console console) {
		if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); }
	}

}
