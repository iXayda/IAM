package com.ixayda.iam.admin.internal;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.admin.AdminRoleCode;
import com.ixayda.iam.admin.AdminRoleOperations;
import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditAuthenticationFactor;
import com.ixayda.iam.audit.AuditEvent;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.audit.AuditEventType;
import com.ixayda.iam.authorization.AdminAccessTokenClaims;
import com.ixayda.iam.authorization.AdminMfaPolicy;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
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
import org.springframework.security.core.authority.FactorGrantedAuthority;
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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
	private AuditEventOperations auditEvents;

	@Autowired
	private AdminMfaPolicy mfaPolicy;

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
		assertThat(authenticated.getAuthorities()).extracting("authority")
			.containsExactlyInAnyOrder("user.read", FactorGrantedAuthority.PASSWORD_AUTHORITY,
					FactorGrantedAuthority.OTT_AUTHORITY);

		this.roles.revoke(tenant.id(), superAdmin.id(), support.id(), supportRole);
		assertThat(this.authenticationConverter.convert(token).getAuthorities()).extracting("authority")
			.doesNotContain("user.read")
			.contains(FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY);

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

	@Test
	void requiresLiveRoleReadPermissionForTheRoleCatalog() throws Exception {
		Tenant tenant = createTenant("role-catalog");
		User superAdmin = createUser(tenant.id(), "super-admin");
		User reader = createUser(tenant.id(), "reader");
		User limited = createUser(tenant.id(), "limited");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), reader.id(), AdminRoleCode.ADMIN_MANAGER,
				"Role catalog access");
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), limited.id(), AdminRoleCode.from("user_manager"),
				"No role catalog access");
		String readerToken = encodedToken(startSession(tenant.id(), reader));
		String limitedToken = encodedToken(startSession(tenant.id(), limited));

		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH))
			.andExpect(status().isUnauthorized());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(limitedToken)))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(readerToken)))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(jsonPath("$.roles", hasSize(5)))
			.andExpect(jsonPath("$.roles[*].code", contains("admin_manager", "auditor", "super_admin", "support",
					"user_manager")))
			.andExpect(jsonPath("$.roles[0].status").value("active"))
			.andExpect(jsonPath("$.roles[0].protectedRole").value(true));

		this.roles.revoke(tenant.id(), superAdmin.id(), reader.id(), AdminRoleCode.ADMIN_MANAGER);
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(readerToken)))
			.andExpect(status().isForbidden());
	}

	@Test
	void requiresARecentLiveSecondFactorForAdminRequests() throws Exception {
		Tenant tenant = createTenant("mfa");
		User admin = createUser(tenant.id(), "admin");
		this.roles.bootstrapSuperAdmin(tenant.id(), admin.id());
		Instant authenticatedAt = Instant.now();
		String passwordOnly = encodedToken(startPasswordOnlySession(tenant.id(), admin, authenticatedAt));
		String expiredMfa = encodedToken(startSession(tenant.id(), admin, authenticatedAt,
				authenticatedAt.minus(this.mfaPolicy.validDuration())));
		String freshMfa = encodedToken(startSession(tenant.id(), admin, authenticatedAt, authenticatedAt));

		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(passwordOnly)))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(expiredMfa)))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.ROLES_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(freshMfa)))
			.andExpect(status().isOk());
	}

	@Test
	void requiresLiveAuditPermissionAndReturnsTenantBoundCursorPages() throws Exception {
		Tenant tenant = createTenant("audit-events");
		Tenant anotherTenant = createTenant("audit-events-other");
		User superAdmin = createUser(tenant.id(), "audit-super-admin");
		User auditor = createUser(tenant.id(), "auditor");
		User limited = createUser(tenant.id(), "audit-limited");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), auditor.id(), AdminRoleCode.from("auditor"),
				"Audit review");
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), limited.id(), AdminRoleCode.from("support"),
				"No audit access");
		Instant occurredAt = Instant.now().plusSeconds(1);
		AuditEvent older = appendAuditEvent(tenant.id(), occurredAt, "older");
		AuditEvent newer = appendAuditEvent(tenant.id(), occurredAt.plusSeconds(1), "newer");
		appendAuditEvent(anotherTenant.id(), occurredAt.plusSeconds(2), "foreign");
		String auditorToken = encodedToken(startSession(tenant.id(), auditor));
		String limitedToken = encodedToken(startSession(tenant.id(), limited));

		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENTS_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(limitedToken)))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENTS_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(auditorToken))
			.queryParam("limit", "1"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(jsonPath("$.events", hasSize(1)))
			.andExpect(jsonPath("$.events[0].id").value(newer.id().toString()))
			.andExpect(jsonPath("$.events[0].type").value("authentication.login.succeeded"))
			.andExpect(jsonPath("$.events[0].source").value("integration:newer"))
			.andExpect(jsonPath("$.events[0].attributes.channel").value("web"))
			.andExpect(jsonPath("$.nextCursor").value(newer.id().toString()));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENTS_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(auditorToken))
			.queryParam("limit", "1")
			.queryParam("before", newer.id().toString()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.events", hasSize(1)))
			.andExpect(jsonPath("$.events[0].id").value(older.id().toString()))
			.andExpect(jsonPath("$.nextCursor").value(older.id().toString()));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENTS_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(auditorToken))
			.queryParam("limit", "201"))
			.andExpect(status().isBadRequest());
	}

	@Test
	void requiresExportPermissionAndReturnsRecordedEventsAsNdjson() throws Exception {
		Tenant tenant = createTenant("audit-export");
		User superAdmin = createUser(tenant.id(), "export-super-admin");
		User auditor = createUser(tenant.id(), "export-auditor");
		this.roles.bootstrapSuperAdmin(tenant.id(), superAdmin.id());
		this.roles.grantPermanent(tenant.id(), superAdmin.id(), auditor.id(), AdminRoleCode.from("auditor"),
				"Read-only audit review");
		AuditEvent firstInserted = appendAuditEvent(tenant.id(), Instant.parse("2026-07-21T02:00:00Z"), "first");
		AuditEvent secondInserted = appendAuditEvent(tenant.id(), Instant.parse("2026-07-21T01:00:00Z"), "second");
		List<AuditEvent> expected = List.of(firstInserted, secondInserted)
			.stream()
			.sorted(Comparator.comparing(AuditEvent::recordedAt).thenComparing(event -> event.id().value()))
			.toList();
		Instant from = expected.getFirst().recordedAt();
		Instant to = expected.getLast().recordedAt().plus(1, ChronoUnit.MICROS);
		String superAdminToken = encodedToken(startSession(tenant.id(), superAdmin));
		String auditorToken = encodedToken(startSession(tenant.id(), auditor));
		String passwordOnlyToken = encodedToken(startPasswordOnlySession(tenant.id(), superAdmin, Instant.now()));

		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(auditorToken))
			.queryParam("from", from.toString())
			.queryParam("to", to.toString()))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(passwordOnlyToken))
			.queryParam("from", from.toString())
			.queryParam("to", to.toString()))
			.andExpect(status().isForbidden());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(superAdminToken))
			.queryParam("from", from.toString())
			.queryParam("to", to.toString())
			.queryParam("limit", "1"))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(header().string(AdminAuditEventController.NEXT_CURSOR_HEADER,
					expected.getFirst().id().toString()))
			.andExpect(content().contentType(AdminAuditEventController.NDJSON_MEDIA_TYPE))
			.andExpect(content().string(org.hamcrest.Matchers.endsWith("\n")))
			.andExpect(jsonPath("$.id").value(expected.getFirst().id().toString()))
			.andExpect(jsonPath("$.source").value(expected.getFirst().source()));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(superAdminToken))
			.queryParam("from", from.toString())
			.queryParam("to", to.toString())
			.queryParam("limit", "1")
			.queryParam("after", expected.getFirst().id().toString()))
			.andExpect(status().isOk())
			.andExpect(header().doesNotExist(AdminAuditEventController.NEXT_CURSOR_HEADER))
			.andExpect(jsonPath("$.id").value(expected.getLast().id().toString()));
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(superAdminToken))
			.queryParam("from", from.toString())
			.queryParam("to", from.toString()))
			.andExpect(status().isBadRequest());
		this.mockMvc.perform(get(AdminWebSecurityConfiguration.AUDIT_EVENT_EXPORT_PATH)
			.header(HttpHeaders.AUTHORIZATION, bearer(superAdminToken))
			.queryParam("from", from.toString())
			.queryParam("to", to.toString())
			.queryParam("after", UUID.randomUUID().toString()))
			.andExpect(status().isBadRequest());
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
		Instant authenticatedAt = Instant.now();
		return startSession(tenantId, user, authenticatedAt, authenticatedAt);
	}

	private UserSession startSession(TenantId tenantId, User user, Instant authenticatedAt, Instant secondFactorAt) {
		return new TransactionTemplate(this.transactionManager).execute(status -> this.sessions.start(tenantId,
				user.id(), SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, authenticatedAt),
						new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, secondFactorAt)),
				SESSION_TTL));
	}

	private UserSession startPasswordOnlySession(TenantId tenantId, User user, Instant authenticatedAt) {
		return new TransactionTemplate(this.transactionManager).execute(status -> this.sessions.start(tenantId,
				user.id(), SessionAuthenticationMethod.PASSWORD,
				Set.of(new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, authenticatedAt)),
				SESSION_TTL));
	}

	private AuditEvent appendAuditEvent(TenantId tenantId, Instant occurredAt, String source) {
		return this.auditEvents.append(new AppendAuditEvent(tenantId,
				AuditEventType.from("authentication.login.succeeded"), AuditEventOutcome.SUCCEEDED, null, null,
				AuditAuthenticationFactor.TOTP, "integration:" + source, occurredAt, Map.of("channel", "web")));
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
