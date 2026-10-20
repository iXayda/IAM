package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.util.Arrays;
import java.util.UUID;

import com.ixayda.iam.model.MfaRecoveryCodeSet;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestoreAdministrators;
import com.ixayda.iam.service.IdentityRestores;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** External two-person authorization precedes this protected terminal interaction with the verified account owner. */
public final class RestoreAdministratorCommand {

	private RestoreAdministratorCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !"recover-restored-admin".equals(args[0])) { throw new IllegalArgumentException("recover-restored-admin accepts no command arguments"); }
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Restored administrator recovery requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Restored administrator recovery requires a non-Web application"); }
		}).run("--spring.flyway.enabled=false", "--spring.datasource.hikari.maximum-pool-size=1", "--spring.datasource.hikari.minimum-idle=0")) {
			execute(console, context.getBean(IdentityRestores.class), context.getBean(IdentityRestoreAdministrators.class));
		}
	}

	static void execute(Console console, IdentityRestores restores, IdentityRestoreAdministrators administrators) {
		UUID correlation = UUID.randomUUID(); UUID userId; MfaRecoveryCodeSet codes;
		char[] password = null; char[] confirmation = null; char[] code = null;
		try {
			console.printf("Restored administrator correlation: %s%n", correlation);
			console.printf("Keep IAM stopped. Verify the existing identity against current authoritative records, obtain independent second-person approval and arrange trusted notification.%n");
			checkOutput(console);
			String operator = console.readLine("Deployment operator: "); String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) { throw new IllegalArgumentException("Deployment attribution is required"); }
			UUID restoreId = canonical(console.readLine("Quarantine UUID from the independent recovery record: "));
			userId = canonical(console.readLine("Verified existing user UUID: "));
			String database = restores.databaseName();
			console.printf("Target database: %s%nRestore: %s%nUser: %s%n", database, restoreId, userId); checkOutput(console);
			if (!("RECOVER:" + database + ":" + restoreId + ":" + userId).equals(console.readLine("Confirm by typing RECOVER:%s:%s:%s: ", database, restoreId, userId))) {
				throw new IllegalStateException("Restored administrator recovery was not confirmed");
			}
			password = console.readPassword("New password: "); confirmation = console.readPassword("Confirm new password: ");
			if (password == null || confirmation == null || !Arrays.equals(password, confirmation)) { throw new IllegalArgumentException("Password confirmation differs"); }
			var audit = new SecurityAuditContext("deployment:" + operator, "deployment:restore-admin:" + reference, correlation);
			var enrollment = administrators.prepare(database, restoreId, userId, new String(password), audit);
			console.printf("Pending preparation committed; repeating recovery for the same user replaces this enrollment. IAM remains quarantined.%n");
			console.printf("TOTP secret (IAM, SHA-1, 6 digits, 30 seconds): %s%nExpires at: %s%n", enrollment.secret(), enrollment.expiresAt()); checkOutput(console);
			code = console.readPassword("New authenticator code: "); if (code == null) { throw new IllegalStateException("Input cancelled"); }
			codes = administrators.complete(database, restoreId, userId, enrollment.factorId(), new String(password), new String(code), audit)
					.orElseThrow(() -> new IllegalStateException("New authenticator was not confirmed"));
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Restored administrator was not confirmed; pending preparation may remain; correlation: " + correlation); }
		finally {
			if (password != null) { Arrays.fill(password, '\0'); } if (confirmation != null) { Arrays.fill(confirmation, '\0'); } if (code != null) { Arrays.fill(code, '\0'); }
		}
		try {
			console.printf("Restored administrator: %s%nRecovery codes (store securely):%n", userId);
			for (String value : codes.codes()) { console.printf("%s%n", value); }
			console.printf("IAM remains quarantined. Notify the owner through the previously verified channel and record delivery.%nCorrelation: %s%n", correlation); checkOutput(console);
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Restored administrator committed; recovery code delivery was not confirmed; correlation: " + correlation); }
	}

	private static UUID canonical(String value) {
		var id = UUID.fromString(value); if (!id.toString().equals(value)) { throw new IllegalArgumentException("Canonical UUID is required"); } return id;
	}
	private static void checkOutput(Console console) { if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); } }
}
