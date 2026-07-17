package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

class UserProfileSchemaIntegrationTests extends ApplicationIntegrationTest {

	private static final UUID USER_ID = UUID.fromString("019d1bd5-219f-7d9a-82c1-332029f5f001");

	@Autowired
	private JdbcClient jdbcClient;

	@AfterEach
	void deleteFixture() {
		this.jdbcClient.sql("DELETE FROM users WHERE user_id = :userId")
			.param("userId", USER_ID)
			.update();
	}

	@Test
	void storesValidatedUnicodeProfileValues() {
		String displayName = "\u827e\u4e3d\u4e1d\u00b7\u9648";
		String formattedName = "\u9648\u827e\u4e3d\u4e1d";
		String givenName = "\u827e\u4e3d\u4e1d";
		String familyName = "\u9648";
		this.jdbcClient.sql("""
				INSERT INTO users
				    (user_id, tenant_id, display_name, formatted_name, given_name, family_name)
				VALUES
				    (:userId, :tenantId, :displayName, :formattedName, :givenName, :familyName)
				""")
			.param("userId", USER_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("displayName", displayName)
			.param("formattedName", formattedName)
			.param("givenName", givenName)
			.param("familyName", familyName)
			.update();

		assertThat(this.jdbcClient.sql("""
				SELECT display_name || '|' || formatted_name || '|' || given_name || '|' || family_name
				FROM users WHERE user_id = :userId
				""")
			.param("userId", USER_ID)
			.query(String.class)
			.single()).isEqualTo(String.join("|", displayName, formattedName, givenName, familyName));
	}

	@ParameterizedTest
	@ValueSource(strings = { "display_name", "formatted_name", "given_name", "family_name" })
	void rejectsInvalidValuesForEveryProfileColumn(String column) {
		assertInvalidProfile(column, " ");
		assertInvalidProfile(column, "a".repeat(201));
		assertInvalidProfile(column, " Alice");
		assertInvalidProfile(column, "Alice ");
		assertInvalidProfile(column, "\u2003Alice");
		assertInvalidProfile(column, "Alice\nAdmin");
	}

	private void assertInvalidProfile(String column, String value) {
		assertThatThrownBy(() -> this.jdbcClient.sql("INSERT INTO users (user_id, tenant_id, " + column
				+ ") VALUES (:userId, :tenantId, :value)")
			.param("userId", USER_ID)
			.param("tenantId", TenantId.DEFAULT.value())
			.param("value", value)
			.update()).isInstanceOf(DataIntegrityViolationException.class);
	}

}
