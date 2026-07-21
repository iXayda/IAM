package com.ixayda.iam.account.internal;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.session.SessionAbsoluteTtl;
import com.ixayda.iam.session.SessionAuthenticationFactor;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class AccountMfaWebSecurityIntegrationTests extends ApplicationIntegrationTest {

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private static final UserId USER_ID = UserId.from("019f5aff-f979-7653-8001-67ea4274fa01");

	private static final SessionAbsoluteTtl SESSION_TTL = new SessionAbsoluteTtl(Duration.ofHours(1));

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SessionOperations sessions;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@BeforeEach
	void createUser() {
		this.jdbcClient.sql("INSERT INTO users (tenant_id, user_id) VALUES (:tenantId, :userId)")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("""
				INSERT INTO user_login_identifiers
				    (tenant_id, user_id, identifier_type, identifier_value, canonical_value)
				VALUES (:tenantId, :userId, 'username', 'account-mfa', 'account-mfa')
				""")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@AfterEach
	void deleteFixtures() {
		this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_totp_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
		this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", TenantId.DEFAULT.value())
			.param("userId", USER_ID.value())
			.update();
	}

	@Test
	void requiresLiveRecentPasswordSessionAndCsrf() throws Exception {
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH))
			.andExpect(status().isUnauthorized());

		UserSession stalePassword = startSession(Set.of(new SessionAuthenticationFactor(
				SessionAuthenticationFactorType.PASSWORD, Instant.now().minus(Duration.ofMinutes(10)))));
		MockHttpSession staleHttpSession = httpSession(stalePassword);
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(staleHttpSession))
			.andExpect(status().isOk());
		this.mockMvc.perform(post(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH)
			.session(staleHttpSession)
			.with(csrf()))
			.andExpect(status().isForbidden());

		UserSession fresh = startSession(null);
		MockHttpSession freshHttpSession = httpSession(fresh);
		this.mockMvc.perform(post(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH)
			.session(freshHttpSession))
			.andExpect(status().isForbidden());

		SecurityContext context = (SecurityContext) freshHttpSession
			.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		context.setAuthentication(AuthorizationUserAuthentication.authenticated(principal(fresh), Set.of()));
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(freshHttpSession))
			.andExpect(status().isUnauthorized());
		assertThat(freshHttpSession.isInvalid()).isTrue();
	}

	@Test
	void enrollsActivatesAndRevokesTotpWithImmediateSessionInvalidation() throws Exception {
		UserSession initial = startSession(null);
		MockHttpSession initialHttpSession = httpSession(initial);

		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.CSRF_PATH).session(initialHttpSession))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(jsonPath("$.headerName").value("X-CSRF-TOKEN"))
			.andExpect(jsonPath("$.parameterName").value("_csrf"))
			.andExpect(jsonPath("$.token").value(matchesPattern(".+")));
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(initialHttpSession))
			.andExpect(status().isOk())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(jsonPath("$.totpEnabled").value(false));

		MvcResult enrollment = this.mockMvc
			.perform(post(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH)
				.session(initialHttpSession)
				.with(csrf()))
			.andExpect(status().isCreated())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
			.andExpect(header().string(HttpHeaders.LOCATION,
					matchesPattern(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH + "/[0-9a-f-]{36}")))
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andExpect(jsonPath("$.secret").value(matchesPattern("[A-Z2-7]{32}")))
			.andExpect(jsonPath("$.provisioningUri").value(matchesPattern("otpauth://totp/.*")))
			.andExpect(jsonPath("$.algorithm").value("SHA1"))
			.andExpect(jsonPath("$.digits").value(6))
			.andExpect(jsonPath("$.periodSeconds").value(30))
			.andReturn();
		assertThat(initialHttpSession.isInvalid()).isFalse();
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(initialHttpSession))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totpEnabled").value(false));

		JsonNode enrollmentBody = JSON.readTree(enrollment.getResponse().getContentAsString());
		String credentialId = enrollmentBody.get("credentialId").asText();
		byte[] secret = decodeBase32(enrollmentBody.get("secret").asText());
		String code = totpCode(secret, Instant.now());
		String wrongCode = (code.charAt(0) == '0' ? '1' : '0') + code.substring(1);
		try {
			this.mockMvc.perform(post(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH + "/"
					+ credentialId + "/activation")
				.session(initialHttpSession)
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"code\":\"" + wrongCode + "\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));

			this.mockMvc.perform(post(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH + "/"
					+ credentialId + "/activation")
				.session(initialHttpSession)
				.with(csrf())
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"code\":\"" + code + "\"}"))
				.andExpect(status().isNoContent())
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
		}
		finally {
			java.util.Arrays.fill(secret, (byte) 0);
		}
		assertThat(initialHttpSession.isInvalid()).isTrue();

		MockHttpSession staleHttpSession = httpSession(initial);
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(staleHttpSession))
			.andExpect(status().isUnauthorized());
		assertThat(staleHttpSession.isInvalid()).isTrue();

		Instant verifiedAt = Instant.now();
		UserSession mfaSession = startSession(Set.of(
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.PASSWORD, verifiedAt),
				new SessionAuthenticationFactor(SessionAuthenticationFactorType.TOTP, verifiedAt)));
		MockHttpSession mfaHttpSession = httpSession(mfaSession);
		this.mockMvc.perform(get(AccountMfaWebSecurityConfiguration.MFA_PATH).session(mfaHttpSession))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.totpEnabled").value(true));
		this.mockMvc.perform(delete(AccountMfaWebSecurityConfiguration.TOTP_PATH)
			.session(mfaHttpSession)
			.with(csrf()))
			.andExpect(status().isNoContent())
			.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
		assertThat(mfaHttpSession.isInvalid()).isTrue();
		assertThat(this.sessions.findUsable(TenantId.DEFAULT, mfaSession.id())).isEmpty();
	}

	private UserSession startSession(Set<SessionAuthenticationFactor> factors) {
		return transactionTemplate().execute(status -> factors == null
				? this.sessions.start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD, SESSION_TTL)
				: this.sessions.start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD, factors, SESSION_TTL));
	}

	private MockHttpSession httpSession(UserSession userSession) {
		MockHttpSession session = new MockHttpSession();
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(AuthorizationUserAuthentication.authenticated(principal(userSession),
				factorAuthorities(userSession)));
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
		return session;
	}

	private static AuthorizationPrincipal principal(UserSession session) {
		return new AuthorizationPrincipal(session.tenantId(), session.userId(), session.id(),
				session.authenticationMethod(), session.authenticatedAt());
	}

	private static Set<GrantedAuthority> factorAuthorities(UserSession session) {
		Map<String, Instant> factors = new LinkedHashMap<>();
		session.authenticationFactors().forEach(factor -> factors.merge(authority(factor.type()), factor.issuedAt(),
				(first, second) -> first.isAfter(second) ? first : second));
		return Set.copyOf(factors.entrySet()
			.stream()
			.map(entry -> (GrantedAuthority) FactorGrantedAuthority.withAuthority(entry.getKey())
				.issuedAt(entry.getValue())
				.build())
			.toList());
	}

	private static String authority(SessionAuthenticationFactorType factor) {
		return switch (factor) {
			case PASSWORD -> FactorGrantedAuthority.PASSWORD_AUTHORITY;
			case TOTP, RECOVERY_CODE -> FactorGrantedAuthority.OTT_AUTHORITY;
		};
	}

	private static byte[] decodeBase32(String value) {
		byte[] decoded = new byte[value.length() * 5 / 8];
		int buffer = 0;
		int bitsLeft = 0;
		int output = 0;
		for (int index = 0; index < value.length(); index++) {
			int digit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(value.charAt(index));
			if (digit < 0) {
				throw new IllegalArgumentException("Invalid Base32 test input");
			}
			buffer = buffer << 5 | digit;
			bitsLeft += 5;
			if (bitsLeft >= 8) {
				decoded[output++] = (byte) (buffer >> bitsLeft - 8 & 0xff);
				bitsLeft -= 8;
			}
		}
		return decoded;
	}

	private static String totpCode(byte[] secret, Instant now) throws GeneralSecurityException {
		long timeStep = now.getEpochSecond() / 30;
		byte[] counter = new byte[Long.BYTES];
		for (int index = counter.length - 1; index >= 0; index--) {
			counter[index] = (byte) timeStep;
			timeStep >>>= 8;
		}
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(new SecretKeySpec(secret, "HmacSHA1"));
		byte[] digest = mac.doFinal(counter);
		int offset = digest[digest.length - 1] & 0x0f;
		int binary = (digest[offset] & 0x7f) << 24 | (digest[offset + 1] & 0xff) << 16
				| (digest[offset + 2] & 0xff) << 8 | digest[offset + 3] & 0xff;
		return "%06d".formatted(binary % 1_000_000);
	}

	private TransactionTemplate transactionTemplate() {
		return new TransactionTemplate(this.transactionManager);
	}

}
