package com.ixayda.iam.security;

import java.util.UUID;

import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.IdentityUserSetups;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(PostgreSqlTestConfiguration.class)
@ActiveProfiles("documentation")
class IdentityHealthOpenApiIntegrationTests extends BrowserHttpTestSupport {

	@Autowired IdentityUsers users;
	@Autowired IdentityUserSetups setups;

	@Test
	void swaggerDescribesPublicGetOnlyProbesWithStatusOnlyResponsesAndNoBrowserAuthenticationErrors() throws Exception {
		var audit = new SecurityAuditContext("system:health-doc-test", "internal:test", UUID.randomUUID());
		var user = this.users.create("alice", "Alice", audit); var setup = this.setups.issue(user.id(), audit);
		String password = "saffron village ripple lantern 936"; this.setups.complete(user.id(), setup.token(), password, "internal:test", UUID.randomUUID());
		try (var http = client()) {
			var csrf = get(http, "/api/csrf", null); var login = post(http, "/login", cookie(csrf), credentials("alice", password, csrf(csrf)));
			assertThat(login.statusCode()).isEqualTo(204);
			var response = get(http, "/v3/api-docs", cookie(login)); assertThat(response.statusCode()).isEqualTo(200);
			var document = new JsonMapper().readTree(response.body());
			for (String path : IdentityHealthRequestFilter.PATHS) {
				var route = document.path("paths").path(path); assertThat(route.propertyNames()).containsExactly("get");
				var operation = route.path("get"); assertThat(operation.path("security").isArray()).isTrue(); assertThat(operation.path("security").size()).isZero();
				assertThat(operation.path("responses").propertyNames()).containsExactlyInAnyOrder("200", "503", "400", "405");
				assertThat(operation.path("responses").path("503").path("content").path("application/json").path("schema").path("$ref").asText()).isEqualTo("#/components/schemas/IdentityHealth");
			}
			var schema = document.path("components").path("schemas").path("IdentityHealth");
			assertThat(schema.path("properties").propertyNames()).containsExactly("status"); assertThat(schema.path("additionalProperties").asBoolean()).isFalse();
		}
	}
}
