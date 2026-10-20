package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.util.Arrays;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestoreRelease;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestoreReleases;
import com.ixayda.iam.service.IdentityRestores;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Final explicit authorization after independent recovery verification and containment of external applications. */
public final class RestoreReleaseCommand {

	private RestoreReleaseCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !"release-restore".equals(args[0])) { throw new IllegalArgumentException("release-restore accepts no command arguments"); }
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Restore release requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Restore release requires a non-Web application"); }
		}).run("--spring.flyway.enabled=false", "--spring.datasource.hikari.maximum-pool-size=1", "--spring.datasource.hikari.minimum-idle=0")) {
			execute(console, context.getBean(IdentityRestores.class), context.getBean(IdentityRestoreReleases.class));
		}
	}

	static void execute(Console console, IdentityRestores restores, IdentityRestoreReleases releases) {
		UUID correlation = UUID.randomUUID(); IdentityRestoreRelease result;
		char[] password = null; char[] code = null;
		try {
			console.printf("Restore release correlation: %s%n", correlation);
			console.printf("Keep IAM stopped. Independently approve this release, verify recovery records and confirm external applications cleared old sessions, tokens and key caches.%n");
			checkOutput(console);
			String operator = console.readLine("Deployment operator: "); String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) { throw new IllegalArgumentException("Deployment attribution is required"); }
			UUID restoreId = canonical(console.readLine("Quarantine UUID from the independent recovery record: "));
			UUID userId = canonical(console.readLine("Recovered administrator user UUID: "));
			UUID signingKeyId = canonical(console.readLine("New signing key UUID: "));
			String database = restores.databaseName();
			console.printf("Target database: %s%nRestore: %s%nAdministrator: %s%nNew signing key: %s%n", database, restoreId, userId, signingKeyId); checkOutput(console);
			if (!("RELEASE:" + database + ":" + restoreId + ":" + userId + ":" + signingKeyId).equals(console.readLine("Confirm by typing RELEASE:%s:%s:%s:%s: ", database, restoreId, userId, signingKeyId))) {
				throw new IllegalStateException("Restore release was not confirmed");
			}
			password = console.readPassword("Current recovered password: "); code = console.readPassword("Fresh authenticator code: ");
			if (password == null || code == null) { throw new IllegalStateException("Input cancelled"); }
			result = releases.release(database, restoreId, userId, signingKeyId, new String(password), new String(code),
					new SecurityAuditContext("deployment:" + operator, "deployment:restore-release:" + reference, correlation))
					.orElseThrow(() -> new IllegalStateException("Restored administrator authentication was rejected"));
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Restore release was not confirmed; correlation: " + correlation); }
		finally { if (password != null) { Arrays.fill(password, '\0'); } if (code != null) { Arrays.fill(code, '\0'); } }
		try {
			console.printf("Restore released: %s%nReleased at: %s%nAudit gap: unresolved%nOther users and applications remain disabled. Reapply runtime grants, start IAM and verify readiness before reopening traffic.%nCorrelation: %s%n", result.restoreId(), result.releasedAt(), correlation);
			checkOutput(console);
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Restore release committed; terminal delivery was not confirmed; correlation: " + correlation); }
	}

	private static UUID canonical(String value) {
		var id = UUID.fromString(value); if (!id.toString().equals(value)) { throw new IllegalArgumentException("Canonical UUID is required"); } return id;
	}
	private static void checkOutput(Console console) { if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); } }
}
