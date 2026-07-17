package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.client.ClientRedirectUri;
import com.ixayda.iam.client.ClientRegistration;
import com.ixayda.iam.client.ClientScope;
import com.ixayda.iam.client.ClientTokenPolicy;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.CreateClientRequest;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.Tenant;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantOperations;
import com.ixayda.iam.user.CreateUserRequest;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@AutoConfigureMockMvc
class AuthorizationLoginWebSecurityIntegrationTests extends ApplicationIntegrationTest {

	private static final String REDIRECT_URI = "https://client.example.test/callback";

	private static final String PASSWORD = "correct-password";

	private static final String ISSUER = "https://issuer.example.test";

	private static final Pattern CONSENT_STATE = Pattern.compile("name=\"state\" value=\"([^\"]+)\"");

	private static final JsonMapper JSON = JsonMapper.builder().build();

	private final List<ClientId> clientsToDelete = new ArrayList<>();

	private final List<UserReference> usersToDelete = new ArrayList<>();

	private final List<TenantId> tenantsToDelete = new ArrayList<>();

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ClientOperations clients;

	@Autowired
	private PasswordOperations passwords;

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private UserOperations users;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private JwtDecoder jwtDecoder;

	@AfterEach
	void deleteFixtures() {
		this.clientsToDelete.forEach((clientId) -> {
			this.jdbcClient.sql("DELETE FROM oauth_authorization_consents WHERE client_id = :clientId")
				.param("clientId", clientId.value())
				.update();
			this.jdbcClient.sql("DELETE FROM oauth_authorizations WHERE client_id = :clientId")
				.param("clientId", clientId.value())
				.update();
		});
		this.usersToDelete.forEach((reference) -> {
			this.jdbcClient.sql("DELETE FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_password_credentials WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM user_login_identifiers WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
			this.jdbcClient.sql("DELETE FROM users WHERE tenant_id = :tenantId AND user_id = :userId")
				.param("tenantId", reference.tenantId().value())
				.param("userId", reference.userId().value())
				.update();
		});
		this.clientsToDelete.forEach((clientId) -> this.jdbcClient
			.sql("DELETE FROM oauth_clients WHERE client_id = :clientId")
			.param("clientId", clientId.value())
			.update());
		this.tenantsToDelete.reversed().forEach((tenantId) -> this.jdbcClient
			.sql("DELETE FROM tenants WHERE tenant_id = :tenantId")
			.param("tenantId", tenantId.value())
			.update());
	}

	@Test
	void servesTheDefaultLoginPageAndRequiresCsrfForCredentialSubmission() throws Exception {
		this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
			.andExpect(content().string(containsString("name=\"username\"")))
			.andExpect(content().string(containsString("name=\"password\"")))
			.andExpect(content().string(containsString("name=\"_csrf\"")));

		this.mockMvc.perform(post("/login").param("username", "alice").param("password", PASSWORD))
			.andExpect(status().isForbidden())
			.andExpect(unauthenticated());
	}

	@Test
	void refusesDirectLoginWithoutASavedAuthorizationRequest() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "direct");

		MvcResult result = this.mockMvc
			.perform(post("/login").with(csrf()).param("username", user.username()).param("password", PASSWORD))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/login?error"))
			.andExpect(unauthenticated())
			.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
		assertThat(result.getRequest().getSession(false).getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION))
			.isInstanceOfSatisfying(BadCredentialsException.class,
					(exception) -> assertThat(exception).hasMessage("Invalid tenant, login, or password"));
		assertThat(sessionCount(user.user())).isZero();
	}

	@Test
	void returnsTheSameFailureForAnIncorrectPassword() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "wrong-password");
		OAuthClient client = createClient(TenantId.DEFAULT, "wrong-password");
		MockHttpSession session = beginAuthorization(client);

		this.mockMvc
			.perform(post("/login").session(session).with(csrf()).param("username", user.username())
				.param("password", "incorrect-password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/login?error"))
			.andExpect(unauthenticated());

		assertThat(session.getAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE))
			.isInstanceOf(SavedRequest.class);
		assertThat(session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION))
			.isInstanceOfSatisfying(BadCredentialsException.class,
					(exception) -> assertThat(exception).hasMessage("Invalid tenant, login, or password"));
		assertThat(sessionCount(user.user())).isZero();
	}

	@Test
	void bindsLoginToTheAuthorizationClientTenantAndRedirectsBackToTheSavedRequest() throws Exception {
		Tenant tenant = createTenant();
		UserFixture user = createUser(tenant.id(), "tenant-bound");
		OAuthClient otherTenantClient = createClient(TenantId.DEFAULT, "other-tenant");
		MockHttpSession rejectedSession = beginAuthorization(otherTenantClient);

		this.mockMvc
			.perform(post("/login").session(rejectedSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/login?error"))
			.andExpect(unauthenticated());

		OAuthClient matchingClient = createClient(tenant.id(), "matching-tenant");
		MockHttpSession acceptedSession = beginAuthorization(matchingClient);
		SavedRequest savedRequest = (SavedRequest) acceptedSession
			.getAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE);
		String sessionIdBeforeLogin = acceptedSession.getId();
		assertThat(savedRequest.getRedirectUrl()).startsWith("https://attacker.example/");

		MvcResult loginResult = this.mockMvc
			.perform(post("/login").session(acceptedSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith("https://issuer.example.test/oauth2/authorize?")))
			.andExpect(authenticated().withAuthentication((authentication) -> {
				assertThat(authentication).isInstanceOf(AuthorizationUserAuthentication.class);
				assertThat(authentication.getPrincipal()).isInstanceOfSatisfying(AuthorizationPrincipal.class,
						(principal) -> {
							assertThat(principal.tenantId()).isEqualTo(tenant.id());
							assertThat(principal.userId()).isEqualTo(user.user().id());
						});
			}))
			.andReturn();

		URI redirect = URI.create(loginResult.getResponse().getHeader("Location"));
		assertThat(redirect.getScheme()).isEqualTo("https");
		assertThat(redirect.getHost()).isEqualTo("issuer.example.test");
		assertThat(redirect.getPath()).isEqualTo("/oauth2/authorize");
		assertThat(redirect.getRawQuery()).contains("client_id=" + matchingClient.identifier().value())
			.doesNotContain("continue");
		MockHttpSession authenticatedSession = (MockHttpSession) loginResult.getRequest().getSession(false);
		assertThat(authenticatedSession.getId()).isNotEqualTo(sessionIdBeforeLogin);
		assertThat(authenticatedSession.getAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE)).isNull();
		assertThat(authenticatedSession.getAttribute("SPRING_SECURITY_CONTEXT"))
			.isInstanceOf(SecurityContext.class);
		assertThat(sessionCount(user.user())).isOne();
	}

	@Test
	void completesTheOpenIdAuthorizationCodeFlowAndEnforcesPkceAndCodeSingleUse() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "authorization-code");
		OAuthClient client = createClient(TenantId.DEFAULT, "authorization-code",
				Set.of(new ClientScope("openid"), new ClientScope("profile")));
		String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
		String challenge = pkceChallenge(verifier);
		String nonce = "nonce-" + suffix();
		String clientState = "client-state-" + suffix();
		MockHttpSession loginSession = beginAuthorization(client, "openid profile", clientState, challenge, nonce);

		MvcResult loginResult = this.mockMvc
			.perform(post("/login").session(loginSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andExpect(authenticated())
			.andReturn();
		MockHttpSession authenticatedSession = (MockHttpSession) loginResult.getRequest().getSession(false);
		URI authorizationContinuation = URI.create(loginResult.getResponse().getHeader("Location"));

		MvcResult consentPage = this.mockMvc
			.perform(get(authorizationContinuation).session(authenticatedSession).accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
			.andExpect(content().string(containsString("Consent required")))
			.andExpect(content().string(containsString("name=\"scope\" value=\"profile\"")))
			.andReturn();
		String consentState = consentState(consentPage.getResponse().getContentAsString());

		MvcResult consentResult = this.mockMvc
			.perform(post("/oauth2/authorize").session(authenticatedSession)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
				.param(OAuth2ParameterNames.STATE, consentState)
				.param(OAuth2ParameterNames.SCOPE, "profile"))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith(REDIRECT_URI + "?")))
			.andReturn();
		URI clientRedirect = URI.create(consentResult.getResponse().getHeader("Location"));
		String authorizationCode = queryParameter(clientRedirect, OAuth2ParameterNames.CODE);
		assertThat(queryParameter(clientRedirect, OAuth2ParameterNames.STATE)).isEqualTo(clientState);
		assertThat(consentState).isNotEqualTo(clientState);
		assertThat(consentAuthorities(client)).containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_profile");
		assertThat(authorizationScopes(client)).containsExactlyInAnyOrder("openid", "profile");
		assertThat(tokenInvalidated(client, "authorization_code")).isFalse();
		assertThat(tokenCount(client)).isOne();
		long revisionWithCode = authorizationRevision(client);

		MvcResult rejectedExchange = this.mockMvc
			.perform(tokenRequest(client, authorizationCode, "wrong-" + verifier))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andReturn();
		assertThat(JSON.readTree(rejectedExchange.getResponse().getContentAsString()).get("error").stringValue())
			.isEqualTo("invalid_grant");
		assertThat(tokenInvalidated(client, "authorization_code")).isFalse();
		assertThat(tokenCount(client)).isOne();
		assertThat(authorizationRevision(client)).isEqualTo(revisionWithCode);

		MvcResult successfulExchange = this.mockMvc.perform(tokenRequest(client, authorizationCode, verifier))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andReturn();
		JsonNode tokenResponse = JSON.readTree(successfulExchange.getResponse().getContentAsString());
		String accessTokenValue = tokenResponse.get("access_token").stringValue();
		String idTokenValue = tokenResponse.get("id_token").stringValue();
		assertThat(tokenResponse.get("token_type").stringValue()).isEqualTo("Bearer");
		assertThat(Set.copyOf(List.of(tokenResponse.get("scope").stringValue().split(" "))))
			.containsExactlyInAnyOrder("openid", "profile");
		assertThat(tokenResponse.get("expires_in").longValue()).isPositive();
		assertThat(tokenResponse.get("refresh_token")).isNull();

		Jwt accessToken = this.jwtDecoder.decode(accessTokenValue);
		assertThat(accessToken.getIssuer()).hasToString(ISSUER);
		assertThat(accessToken.getSubject()).isEqualTo(user.user().id().toString());
		assertThat(accessToken.getAudience()).containsExactly(client.identifier().value());
		assertThat(accessToken.getClaimAsStringList("scope")).containsExactlyInAnyOrder("openid", "profile");
		Jwt idToken = this.jwtDecoder.decode(idTokenValue);
		assertThat(idToken.getIssuer()).hasToString(ISSUER);
		assertThat(idToken.getSubject()).isEqualTo(user.user().id().toString());
		assertThat(idToken.getAudience()).containsExactly(client.identifier().value());
		assertThat(idToken.getClaimAsString("nonce")).isEqualTo(nonce);
		assertThat(tokenCount(client)).isEqualTo(3);
		assertThat(tokenInvalidated(client, "authorization_code")).isTrue();
		assertThat(tokenInvalidated(client, "access_token")).isFalse();
		assertThat(tokenInvalidated(client, "id_token")).isFalse();
		assertThat(accessTokenScopeCount(client)).isEqualTo(2);
		assertThat(authorizationRevision(client)).isEqualTo(revisionWithCode + 1);

		MvcResult replay = this.mockMvc.perform(tokenRequest(client, authorizationCode, verifier))
			.andExpect(status().isBadRequest())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andReturn();
		assertThat(JSON.readTree(replay.getResponse().getContentAsString()).get("error").stringValue())
			.isEqualTo("invalid_grant");
		assertThat(tokenInvalidated(client, "authorization_code")).isTrue();
		assertThat(tokenInvalidated(client, "access_token")).isTrue();
		assertThat(tokenInvalidated(client, "id_token")).isFalse();
		assertThat(tokenCount(client)).isEqualTo(3);
		assertThat(authorizationRevision(client)).isEqualTo(revisionWithCode + 2);
	}

	private MockHttpSession beginAuthorization(OAuthClient client) throws Exception {
		return beginAuthorization(client, "openid", "state-value", "A".repeat(43), null);
	}

	private MockHttpSession beginAuthorization(OAuthClient client, String scopes, String state, String challenge,
			String nonce) throws Exception {
		MockHttpServletRequestBuilder authorizationRequest = get("/oauth2/authorize").accept(MediaType.TEXT_HTML)
			.with((request) -> {
				request.setScheme("https");
				request.setServerName("attacker.example");
				request.setServerPort(443);
				return request;
			})
			.header("Forwarded", "host=forwarded-attacker.example;proto=https")
			.header("X-Forwarded-Host", "forwarded-attacker.example")
			.queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
			.queryParam(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
			.queryParam(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI)
			.queryParam(OAuth2ParameterNames.SCOPE, scopes)
			.queryParam(OAuth2ParameterNames.STATE, state)
			.queryParam(PkceParameterNames.CODE_CHALLENGE, challenge)
			.queryParam(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		if (nonce != null) {
			authorizationRequest.queryParam("nonce", nonce);
		}
		MvcResult result = this.mockMvc
			.perform(authorizationRequest)
			.andExpect(status().isFound())
			.andExpect(header().string("Location", endsWith("/login")))
			.andExpect(unauthenticated())
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		assertThat(session.getAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE))
			.isInstanceOf(SavedRequest.class);
		return session;
	}

	private OAuthClient createClient(TenantId tenantId, String purpose) {
		return createClient(tenantId, purpose, Set.of(new ClientScope("openid")));
	}

	private OAuthClient createClient(TenantId tenantId, String purpose, Set<ClientScope> scopes) {
		String identifier = "login-" + purpose + "-" + suffix();
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier(identifier), "Authorization Login Client",
				ClientType.PUBLIC, ClientAuthenticationMethod.NONE, Set.of(new ClientRedirectUri(REDIRECT_URI)), Set.of(),
				scopes, ClientTokenPolicy.secureDefaults());
		try (ClientRegistration registration = this.clients.create(tenantId, request)) {
			this.clientsToDelete.add(registration.client().id());
			return registration.client();
		}
	}

	private UserFixture createUser(TenantId tenantId, String purpose) {
		String username = "login-" + purpose + "-" + suffix();
		User user = this.users.create(tenantId,
				new CreateUserRequest(List.of(LoginIdentifier.username(username))));
		this.usersToDelete.add(new UserReference(tenantId, user.id()));
		try (NewPassword password = new NewPassword(PASSWORD.toCharArray())) {
			this.passwords.setPassword(tenantId, user.id(), password);
		}
		return new UserFixture(user, username);
	}

	private Tenant createTenant() {
		Tenant tenant = this.tenants
			.create(new CreateTenantRequest("login-" + suffix(), "Authorization Login Tenant"));
		this.tenantsToDelete.add(tenant.id());
		return tenant;
	}

	private int sessionCount(User user) {
		return this.jdbcClient.sql("SELECT count(*) FROM user_sessions WHERE tenant_id = :tenantId AND user_id = :userId")
			.param("tenantId", user.tenantId().value())
			.param("userId", user.id().value())
			.query(Integer.class)
			.single();
	}

	private List<String> consentAuthorities(OAuthClient client) {
		return this.jdbcClient.sql("""
				SELECT authority
				FROM oauth_authorization_consent_authorities
				WHERE client_id = :clientId
				""")
			.param("clientId", client.id().value())
			.query(String.class)
			.list();
	}

	private List<String> authorizationScopes(OAuthClient client) {
		return this.jdbcClient.sql("""
				SELECT scope
				FROM oauth_authorization_scopes
				WHERE client_id = :clientId
				""")
			.param("clientId", client.id().value())
			.query(String.class)
			.list();
	}

	private int accessTokenScopeCount(OAuthClient client) {
		return count("SELECT count(*) FROM oauth_authorization_token_scopes WHERE client_id = :clientId", client);
	}

	private int tokenCount(OAuthClient client) {
		return count("SELECT count(*) FROM oauth_authorization_tokens WHERE client_id = :clientId", client);
	}

	private int count(String query, OAuthClient client) {
		return this.jdbcClient.sql(query)
			.param("clientId", client.id().value())
			.query(Integer.class)
			.single();
	}

	private long authorizationRevision(OAuthClient client) {
		return this.jdbcClient.sql("SELECT version FROM oauth_authorizations WHERE client_id = :clientId")
			.param("clientId", client.id().value())
			.query(Long.class)
			.single();
	}

	private boolean tokenInvalidated(OAuthClient client, String tokenType) {
		return this.jdbcClient.sql("""
				SELECT invalidated_at IS NOT NULL
				FROM oauth_authorization_tokens
				WHERE client_id = :clientId AND token_type = :tokenType
				""")
			.param("clientId", client.id().value())
			.param("tokenType", tokenType)
			.query(Boolean.class)
			.single();
	}

	private static MockHttpServletRequestBuilder tokenRequest(OAuthClient client, String code, String verifier) {
		return post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
			.param(OAuth2ParameterNames.CODE, code)
			.param(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI)
			.param(PkceParameterNames.CODE_VERIFIER, verifier);
	}

	private static String pkceChallenge(String verifier) throws Exception {
		byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	private static String consentState(String page) {
		Matcher matcher = CONSENT_STATE.matcher(page);
		assertThat(matcher.find()).as("consent state field").isTrue();
		return matcher.group(1);
	}

	private static String queryParameter(URI uri, String name) {
		String value = UriComponentsBuilder.fromUri(uri).build().getQueryParams().getFirst(name);
		assertThat(value).as("query parameter %s", name).isNotBlank();
		return value;
	}

	private static String suffix() {
		return UUID.randomUUID().toString().substring(0, 8);
	}

	private record UserFixture(User user, String username) {
	}

	private record UserReference(TenantId tenantId, UserId userId) {
	}

}
