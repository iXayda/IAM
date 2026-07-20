package com.ixayda.iam.admin.internal;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.admin.AdminRoleCode;
import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class AdminWebSecurityIntegrationTests extends ApplicationIntegrationTest {

	private static final String ISSUER = "https://issuer.example.test";

	private static final String AUDIENCE = "https://admin.example.test/iam/admin";

	private static final SessionAbsoluteTtl SESSION_TTL = new SessionAbsoluteTtl(Duration.ofHours(8));

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private AdminJwtAuthenticationConverter authenticationConverter;

	@Autowired
	private AdminRoleOperations roles;

	@Autowired
	private SessionOperations sessions;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private UserOperations users;

	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.tenantsToDelete.reversed().forEach(tenantId -> {
			this.jdbcClient.sql("DELETE FROM admin_role_bindings WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
				.param("tenantId", tenantId.value())
				.update();
		});
	}

	@Test
	void resolvesPermissionsAtRequestTimeAndRejectsRevokedSessions() {
		Tenant tenant = createTenant("permissions");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User support = createUser(tenant.id(), "support");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		AdminRoleCode supportRole = AdminRoleCode.from("support");
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), support.id(), supportRole, "Support rotation");
		UserSession session = startSession(tenant.id(), support);
		Jwt token = token(session);

		AuthorizationUserAuthentication authenticated = this.authenticationConverter.convert(token);

		assertThat(authenticated.getPrincipal()).isEqualTo(principal(session));
		assertThat(authenticated.getAuthorities()).extracting("authority").containsExactly("user.read");

		this.roles.revoke(tenant.id(), superAdmin.id(), support.id(), supportRole);
		assertThat(this.authenticationConverter.convert(token).getAuthorities()).isEmpty();

		this.sessions.revoke(tenant.id(), session.id());
		assertThatThrownBy(() -> this.authenticationConverter.convert(token))
			.isInstanceOf(InvalidBearerTokenException.class)
			.hasMessage("The admin token session is invalid.");
	}

	@Test
	void appliesStatelessBearerAuthenticationAndDeniesUnlistedAdminRoutes() throws Exception {
		Tenant tenant = createTenant("web");
		User user = createUser(tenant.id(), "user");
		UserSession session = startSession(tenant.id(), user);
		String token = encodedToken(session);

		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted")
			.header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted")
			.header(HttpHeaders.AUTHORIZATION, bearer(token), bearer(token)))
			.andExpect(status().isBadRequest())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_request\"")));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted")
			.queryParam("access_token", token))
			.andExpect(status().isUnauthorized());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted")
			.header(HttpHeaders.AUTHORIZATION, bearer(token)))
			.andExpect(status().isForbidden());

		this.sessions.revoke(tenant.id(), session.id());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.BASE_PATH + "/unlisted")
			.header(HttpHeaders.AUTHORIZATION, bearer(token)))
			.andExpect(status().isUnauthorized())
			.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));
	}

	private Tenant createTenant(String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		Tenant tenant = this.tenants.create(new CreateTenantRequest("admin-web-" + purpose + "-" + suffix,
				"Admin Web Tenant"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private User createUser(TenantId tenantId, String purpose) {
		String suffix = UUID.randomUUID().toString().substring(0, 8);
		return this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username("admin-web-" + purpose + "-" + suffix))));
	}

	private UserSession startSession(TenantId tenantId, User user) {
		return new TransactionTemplate(this.transactionManager).execute(status -> this.sessions.start(tenantId,
				user.id(), SessionAuthenticationMethod.PASSWORD, SESSION_TTL));
	}

	private String encodedToken(UserSession session) {
		Instant issuedAt = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
			.issuer(ISSUER)
			.subject(session.userId().toString())
			.audience(List.of(AUDIENCE))
			.issuedAt(issuedAt)
			.notBefore(issuedAt)
			.expiresAt(issuedAt.plusSeconds(300))
			.claim("scope", List.of(AdminAccessTokenClaims.SCOPE))
			.claim(AdminAccessTokenClaims.TENANT_ID, session.tenantId().toString())
			.claim(AdminAccessTokenClaims.USER_ID, session.userId().toString())
			.claim(AdminAccessTokenClaims.SESSION_ID, session.id().toString())
			.claim(AdminAccessTokenClaims.AUTHENTICATION_METHOD, "password")
			.claim(AdminAccessTokenClaims.AUTHENTICATION_TIME, session.authenticatedAt().getEpochSecond())
			.build();
		return this.jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
			.getTokenValue();
	}

	private static Jwt token(UserSession session) {
		Instant issuedAt = session.authenticatedAt().plusSeconds(1);
		return new Jwt("token", issuedAt, issuedAt.plusSeconds(300), Map.of("alg", "RS256"),
				Map.of("sub", session.userId().toString(), "scope", List.of(AdminAccessTokenClaims.SCOPE),
						AdminAccessTokenClaims.TENANT_ID, session.tenantId().toString(),
						AdminAccessTokenClaims.USER_ID, session.userId().toString(),
						AdminAccessTokenClaims.SESSION_ID, session.id().toString(),
						AdminAccessTokenClaims.AUTHENTICATION_METHOD, "password",
						AdminAccessTokenClaims.AUTHENTICATION_TIME, session.authenticatedAt().getEpochSecond()));
	}

	private static AuthorizationPrincipal principal(UserSession session) {
		return new AuthorizationPrincipal(session.tenantId(), session.userId(), session.id(),
				session.authenticationMethod(), session.authenticatedAt());
	}

	private static String bearer(String token) {
		return "Bearer " + token;
	}

}
