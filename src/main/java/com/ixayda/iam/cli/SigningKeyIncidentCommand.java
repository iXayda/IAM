package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentitySigningKeyIncidents;
import com.ixayda.iam.service.IdentitySigningKeys;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Explicit maintenance containment and replacement; no key material is accepted or displayed. */
public final class SigningKeyIncidentCommand {

	private SigningKeyIncidentCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !Set.of("compromise-signing-key", "recover-signing-key").contains(args[0])) {
			throw new IllegalArgumentException("Signing key incident commands accept no command arguments");
		}
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Signing key incident commands require an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Signing key incident commands require a non-Web application"); }
		}).run()) {
			execute(console, context.getBean(IdentitySigningKeys.class), context.getBean(IdentitySigningKeyIncidents.class), args[0].equals("recover-signing-key"));
		}
	}

	static void execute(Console console, IdentitySigningKeys keys, IdentitySigningKeyIncidents incidents, boolean recovery) {
		UUID correlation = UUID.randomUUID(); String result;
		try {
			console.printf("Signing key incident correlation: %s%n", correlation); checkOutput(console);
			String operator = console.readLine("Deployment operator: "); String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
				throw new IllegalArgumentException("Deployment operator and authorization reference are required");
			}
			for (var key : keys.metadata()) { console.printf("Signing key: %s  status: %s  created: %s%n", key.id(), key.status(), key.createdAt()); }
			checkOutput(console);
			String selection = console.readLine("Affected signing key UUID: "); UUID id = UUID.fromString(selection);
			if (!id.toString().equals(selection)) { throw new IllegalArgumentException("Canonical signing key UUID is required"); }
			String action = recovery ? "RECOVER" : "COMPROMISE";
			if (!(action + ":" + id).equals(console.readLine("Confirm by typing %s:%s: ", action, id))) { throw new IllegalStateException("Incident action was not confirmed"); }
			var audit = new SecurityAuditContext("deployment:" + operator, "deployment:signing-incident:" + reference, correlation);
			if (recovery) { result = "Replacement signing key created: " + keys.recover(id, audit).id(); }
			else { result = "Signing key compromised: " + id + "; authorizations revoked: " + incidents.compromise(id, audit); }
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Signing key incident action was not confirmed; correlation: " + correlation); }
		try {
			console.printf("%s%nCorrelation: %s%n", result, correlation); checkOutput(console);
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Signing key incident action committed; terminal delivery was not confirmed; correlation: " + correlation); }
	}

	private static void checkOutput(Console console) { if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); } }
}
