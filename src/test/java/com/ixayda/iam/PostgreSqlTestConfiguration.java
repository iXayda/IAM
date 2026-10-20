package com.ixayda.iam;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@TestConfiguration(proxyBeanMethods = false)
@PropertySource("classpath:owner-fixture.properties")
public class PostgreSqlTestConfiguration {

	@Bean
	@org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization
	org.springframework.beans.factory.InitializingBean authorizationProtectionFixture(
			com.ixayda.iam.service.IdentityAuthorizationProtection protection, org.springframework.core.env.Environment environment) {
		return () -> {
			if (!environment.getProperty("iam.authorization.key-file", "").isEmpty()) { protection.initializeForInstallation(); }
		};
	}

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgres() {
		// PostgreSQL 18.6 on Alpine.
		return new PostgreSQLContainer(
				"postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");
	}

}
