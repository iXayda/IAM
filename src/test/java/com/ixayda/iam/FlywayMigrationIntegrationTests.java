package com.ixayda.iam;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class FlywayMigrationIntegrationTests extends ApplicationIntegrationTest {

	@Autowired
	private Flyway flyway;

	@Autowired
	private JdbcClient jdbcClient;

	@Test
	void createsTheBuiltInTenant() {
		assertThat(count("SELECT count(*) FROM flyway_schema_history WHERE success")).isOne();
		assertThat(count("SELECT count(*) FROM tenants")).isOne();
		assertThat(this.jdbcClient.sql("SELECT status FROM tenants WHERE slug = 'default'")
			.query(String.class)
			.single()).isEqualTo("active");
	}

	@Test
	void protectsTenantInvariants() {
		assertThatThrownBy(() -> this.jdbcClient.sql("UPDATE tenants SET status = 'disabled' WHERE slug = 'default'")
			.update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbcClient.sql("""
				INSERT INTO tenants (tenant_id, slug, display_name)
				VALUES ('00000000-0000-0000-0000-000000000002', 'Invalid Slug', 'Invalid')
				""").update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(this.jdbcClient.sql("SELECT status FROM tenants WHERE slug = 'default'")
			.query(String.class)
			.single()).isEqualTo("active");
	}

	@Test
	void aSecondMigrationIsANoOp() {
		assertThat(this.flyway.migrate().migrationsExecuted).isZero();
	}

	private int count(String sql) {
		return this.jdbcClient.sql(sql).query(Integer.class).single();
	}

}
