package com.ixayda.iam.cli;

import java.io.Console;
import java.io.IOError;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentitySigningKeys;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.context.WebApplicationContext;

/** Maintenance entry point; uses a protected local terminal and maintenance database credentials. */
public final class SigningKeyRotationCommand {

	private SigningKeyRotationCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !"rotate-signing-key".equals(args[0])) { throw new IllegalArgumentException("rotate-signing-key accepts no command arguments"); }
		Console console = System.console();
		if (console == null) { throw new IllegalStateException("Signing key rotation requires an interactive terminal"); }
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Signing key rotation requires a non-Web application"); }
		}).run()) {
			execute(console, context.getBean(IdentitySigningKeys.class));
		}
	}

	static void execute(Console console, IdentitySigningKeys keys) {
		UUID correlation = UUID.randomUUID(); UUID current; UUID next;
		try {
			console.printf("Signing key rotation correlation: %s%n", correlation); checkOutput(console);
			String operator = console.readLine("Deployment operator: ");
			String reference = console.readLine("Authorization reference: ");
			if (operator == null || !operator.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}")
					|| reference == null || !reference.matches("[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}")) {
				throw new IllegalArgumentException("Deployment operator and authorization reference are required");
			}
			current = keys.findPublicKey().orElseThrow(() -> new IllegalStateException("No current signing key")).id();
			console.printf("Current signing key: %s%n", current); checkOutput(console);
			String confirmation = console.readLine("Confirm rotation by entering the current key UUID: ");
			if (!current.toString().equals(confirmation)) { throw new IllegalStateException("Rotation confirmation failed"); }
			next = keys.rotate(current, new SecurityAuditContext("deployment:" + operator, "deployment:signing-rotation:" + reference, correlation)).id();
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Signing key rotation was not confirmed; correlation: " + correlation); }
		try {
			console.printf("Signing key rotated: %s%nPrevious public key retained for 330 seconds: %s%nCorrelation: %s%n", next, current, correlation);
			checkOutput(console);
		}
		catch (RuntimeException | IOError ex) { throw new IllegalStateException("Signing key rotated; terminal delivery was not confirmed; correlation: " + correlation); }
	}

	private static void checkOutput(Console console) { if (console.writer().checkError()) { throw new IllegalStateException("Terminal output failed"); } }
}
