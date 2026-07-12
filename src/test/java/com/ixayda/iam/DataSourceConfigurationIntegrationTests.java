package com.ixayda.iam;

import static org.assertj.core.api.Assertions.assertThat;

import javax.sql.DataSource;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class DataSourceConfigurationIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private DataSource dataSource;

	@Test
	void suppressesPostgresServerErrorDetails() throws Exception {
		HikariDataSource hikariDataSource = this.dataSource.unwrap(HikariDataSource.class);

		assertThat(hikariDataSource.getDataSourceProperties().getProperty("logServerErrorDetail")).isEqualTo("false");
	}

}
