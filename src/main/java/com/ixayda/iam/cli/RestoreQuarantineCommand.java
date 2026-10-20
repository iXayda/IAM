package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

import com.ixayda.iam.model.IdentityRestore;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityRestores;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Offline, explicitly confirmed quarantine. The archive is read only to verify independently recorded evidence. */
public final class RestoreQuarantineCommand {

	private RestoreQuarantineCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !"quarantine-restore".equals(args[0])) { throw new IllegalArgumentException("quarantine-restore accepts no command arguments"); }
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Restore quarantine requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE)
				.initializers(candidate -> {
					if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Restore quarantine requires a non-Web application"); }
				}).run("--spring.flyway.enabled=false", "--spring.datasource.hikari.maximum-pool-size=1", "--spring.datasource.hikari.minimum-idle=0")) {
			execute(console, context.getBean(IdentityRestores.class));
		}
	}

	static void execute(Console console, IdentityRestores restores) {
		UUID correlation = UUID.randomUUID(); IdentityRestore result;
		try {
			console.printf("Restore quarantine correlation: %s%n", correlation);
			console.printf("Stop IAM and all database clients; verify the archive and recovery authorization independently.%n");
			checkOutput(console);
			String operator = console.readLine("Deployment operator: "); String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
				throw new IllegalArgumentException("Deployment operator and authorization reference are required");
			}
			String checksum = console.readLine("Independently recorded archive SHA-256: ");
			if (checksum == null || !checksum.matches("[0-9a-f]{64}")) { throw new IllegalArgumentException("Canonical SHA-256 is required"); }
			String archive = console.readLine("Verified local archive path: ");
			if (archive == null || !checksum.equals(sha256(Path.of(archive)))) { throw new IllegalArgumentException("Archive checksum differs"); }
			String database = restores.databaseName();
			console.printf("Target database: %s%nAll restored identities and applications will be disabled; credentials, sessions and grants will be invalidated.%n", database);
			checkOutput(console);
			if (!("QUARANTINE:" + database).equals(console.readLine("Confirm by typing QUARANTINE:%s: ", database))) {
				throw new IllegalStateException("Restore quarantine was not confirmed");
			}
			result = restores.quarantine(database, checksum, new SecurityAuditContext("deployment:" + operator, "deployment:restore:" + reference, correlation));
		}
		catch (RuntimeException | IOException | IOError ex) { throw new IllegalStateException("Restore quarantine was not confirmed; correlation: " + correlation); }
		try {
			console.printf("Restore quarantined: %s%nSnapshot audit records: %s%nAudit gap: unresolved%nKeep IAM stopped pending verified recovery.%nCorrelation: %s%n",
					result.id(), result.snapshotAuditCount(), correlation);
			checkOutput(console);
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Restore quarantine committed; terminal delivery was not confirmed; correlation: " + correlation); }
	}

	private static String sha256(Path archive) throws IOException {
		if (!Files.isRegularFile(archive)) { throw new IllegalArgumentException("Regular archive file is required"); }
		try (var input = Files.newInputStream(archive)) {
			var digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[64 * 1024]; int read;
			while ((read = input.read(buffer)) != -1) { digest.update(buffer, 0, read); }
			return HexFormat.of().formatHex(digest.digest());
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 is unavailable"); }
	}

	private static void checkOutput(Console console) { if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); } }
}
