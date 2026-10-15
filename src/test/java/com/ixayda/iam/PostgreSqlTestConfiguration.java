package com.ixayda.iam;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

@TestConfiguration(proxyBeanMethods = false)
public class PostgreSqlTestConfiguration {

	@Bean
	@ServiceConnection
	PostgreSQLContainer postgres() {
		// PostgreSQL 18.6 on Alpine.
		return new PostgreSQLContainer(
				"postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873");
	}

}
