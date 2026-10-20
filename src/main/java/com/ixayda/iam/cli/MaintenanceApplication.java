package com.ixayda.iam.cli;

import java.sql.SQLException;
import java.util.Map;

import javax.sql.DataSource;

import com.ixayda.iam.service.IdentityDatabaseAccess;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.MigrationState;
import org.flywaydb.core.api.callback.BaseCallback;
import org.flywaydb.core.api.callback.Callback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.flyway.autoconfigure.FlywayMigrationStrategy;
import org.springframework.boot.flyway.autoconfigure.FlywayProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.web.context.WebApplicationContext;

/** Offline admission policy shared by every maintenance command. */
final class MaintenanceApplication {

	private MaintenanceApplication() { }

	static ConfigurableApplicationContext start(Class<?> application, String command) {
		boolean migrate = "migrate".equals(command);
		var builder = new SpringApplicationBuilder(application).web(WebApplicationType.NONE).initializers(candidate -> {
			if (candidate instanceof WebApplicationContext) { throw new IllegalStateException("Maintenance requires a non-Web application"); }
			if (!Binder.get(candidate.getEnvironment()).bind("spring.datasource.hikari.connection-init-sql", String.class).orElse("").isBlank()) {
				throw new IllegalStateException("Maintenance forbids Hikari connection initialization SQL before database owner admission");
			}
			if (!migrate) {
				candidate.getEnvironment().getPropertySources().addFirst(new MapPropertySource("iamMaintenanceDatabasePolicy",
						Map.of("spring.flyway.enabled", false)));
			}
			if ("quarantine-restore".equals(command) || "recover-restored-admin".equals(command) || "release-restore".equals(command)) {
				candidate.getEnvironment().getPropertySources().addFirst(new MapPropertySource("iamRestoreDatabasePool",
						Map.of("spring.datasource.hikari.maximum-pool-size", 1, "spring.datasource.hikari.minimum-idle", 0)));
			}
		});
		if (migrate) { builder.sources(MigrationAdmission.class); }
		var context = builder.run();
		try {
			if (!migrate) {
				IdentityDatabaseAccess.requireMaintenanceOwner(context.getBean(DataSource.class));
				try { validateSchema(context); }
				catch (FlywayException failure) {
					throw new IllegalStateException("Maintenance requires the database owner and exact current schema; run the matching migrate command first", failure);
				}
			}
			return context;
		}
		catch (RuntimeException | Error failure) { context.close(); throw failure; }
	}

	static class MigrationAdmission {
		@Bean
		FlywayMigrationStrategy ownerMigration(DataSource businessDataSource) {
			return flyway -> {
				String initSql = flyway.getConfiguration().getInitSql();
				if (initSql != null && !initSql.isBlank()) {
					throw new IllegalStateException("Maintenance forbids Flyway connection initialization SQL before database owner admission");
				}
				IdentityDatabaseAccess.requireMaintenanceOwner(businessDataSource);
				flyway.migrate();
			};
		}

		@Bean
		Callback databaseOwnerAdmission() {
			return new BaseCallback() {
				@Override public boolean supports(Event event, Context context) { return event == Event.AFTER_CONNECT; }
				@Override public void handle(Event event, Context context) {
					IdentityDatabaseAccess.requireMaintenanceOwner(new SingleConnectionDataSource(context.getConnection(), true));
				}
			};
		}
	}

	private static void validateSchema(ConfigurableApplicationContext context) {
		var properties = Binder.get(context.getEnvironment()).bind("spring.flyway", FlywayProperties.class).orElseGet(FlywayProperties::new);
		String businessSchema = context.getBean(IdentityDatabaseAccess.class).requireMaintenanceSchema();
		String configuredSchema = properties.getDefaultSchema();
		if (configuredSchema == null && !properties.getSchemas().isEmpty()) { configuredSchema = properties.getSchemas().getFirst(); }
		if (configuredSchema != null && !configuredSchema.equals(businessSchema)) {
			throw new IllegalStateException("Maintenance migration history must belong to the resolved business schema");
		}
		// Check the business connection against this artifact's complete migration set. Deployment
		// target/ignore settings must not admit pending or newer schemas for maintenance mutations.
		// Flyway opens main and callback connections even for validation. Share one borrowed
		// connection so offline restore admission can retain its single-connection pool.
		try (var connection = context.getBean(DataSource.class).getConnection()) {
			var configuration = Flyway.configure().dataSource(new SingleConnectionDataSource(connection, true))
					.locations("classpath:db/migration").table(properties.getTable())
					.schemas(properties.getSchemas().toArray(String[]::new)).defaultSchema(businessSchema)
					.createSchemas(false).ignoreMigrationPatterns(new String[0]);
			var flyway = configuration.load();
			flyway.validate();
			var migrations = flyway.info().all();
			if (migrations.length == 0) { throw new IllegalStateException("Maintenance requires the current database schema; run migrate first"); }
			for (var migration : migrations) {
				if (migration.getState() != MigrationState.SUCCESS) {
					throw new IllegalStateException("Maintenance requires the exact current database schema; run the matching migrate command first");
				}
			}
		}
		catch (SQLException failure) { throw new IllegalStateException("Maintenance schema validation could not acquire its database connection", failure); }
	}
}
