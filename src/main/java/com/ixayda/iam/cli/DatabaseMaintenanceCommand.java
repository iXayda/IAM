package com.ixayda.iam.cli;

import com.ixayda.iam.service.IdentitySigningKeys;

import org.flywaydb.core.Flyway;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.context.WebApplicationContext;

/** Offline installation entry points; credentials and protection files come from the deployment environment. */
public final class DatabaseMaintenanceCommand {

	private DatabaseMaintenanceCommand() { }

	public static void run(Class<?> application, String[] args) {
		if (args.length != 1 || !("migrate".equals(args[0]) || "initialize-signing-key".equals(args[0]))) {
			throw new IllegalArgumentException("Database maintenance accepts only migrate or initialize-signing-key without arguments");
		}
		try (var context = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Database maintenance requires a non-Web application"); }
		}).run()) {
			execute(context, args[0]);
		}
	}

	static void execute(ConfigurableApplicationContext context, String command) {
		if (context instanceof WebApplicationContext) { throw new IllegalStateException("Database maintenance requires a non-Web application"); }
		if ("migrate".equals(command)) {
			// Boot completes migration before returning the context. Disabled Flyway must not report success.
			var flyway = context.getBean(Flyway.class);
			flyway.validate();
			if (flyway.info().pending().length != 0) { throw new IllegalStateException("Database migrations remain pending"); }
			System.out.println("Database migrations complete");
		}
		else if ("initialize-signing-key".equals(command)) {
			var key = context.getBean(IdentitySigningKeys.class).initializeForInstallation();
			System.out.println("Signing key ready: " + key.id());
		}
		else { throw new IllegalArgumentException("Unknown database maintenance command"); }
	}
}
