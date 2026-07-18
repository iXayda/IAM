package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import com.ixayda.iam.client.ClientAuthenticationMethod;
import com.ixayda.iam.client.ClientAuthorizationGrant;
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
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
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

	private static final Pattern CSRF_TOKEN = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"");

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
	private SessionOperations sessions;

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
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith(ISSUER + AuthorizationConsentController.CONSENT_PATH + "?")))
			.andReturn();
		URI consentUri = URI.create(consentPage.getResponse().getHeader("Location"));
		URI tamperedConsentUri = UriComponentsBuilder.fromUriString(ISSUER + AuthorizationConsentController.CONSENT_PATH)
			.replaceQueryParam(OAuth2ParameterNames.SCOPE, "openid email")
			.queryParam(OAuth2ParameterNames.CLIENT_ID,
					queryParameter(consentUri, OAuth2ParameterNames.CLIENT_ID))
			.queryParam(OAuth2ParameterNames.STATE, URLDecoder.decode(
					queryParameter(consentUri, OAuth2ParameterNames.STATE), StandardCharsets.UTF_8))
			.build()
			.encode()
			.toUri();
		assertThat(queryParameter(tamperedConsentUri, OAuth2ParameterNames.STATE))
			.isEqualTo(queryParameter(consentUri, OAuth2ParameterNames.STATE));
		assertThat(queryParameter(tamperedConsentUri, OAuth2ParameterNames.CLIENT_ID))
			.isEqualTo(queryParameter(consentUri, OAuth2ParameterNames.CLIENT_ID));
		this.mockMvc.perform(get(tamperedConsentUri).session(authenticatedSession).accept(MediaType.TEXT_HTML))
			.andExpect(status().isBadRequest());
		consentPage = this.mockMvc.perform(get(consentUri).session(authenticatedSession).accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
			.andExpect(content().string(containsString("Authorize access")))
			.andExpect(content().string(containsString("name=\"scope\" value=\"profile\"")))
			.andExpect(header().string("Content-Security-Policy", containsString("form-action 'self'")))
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

	@Test
	void refreshesTokensForAnExplicitlyEnabledConfidentialClient() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "refresh-token");
		try (ConfidentialClientFixture client = createRefreshClient(TenantId.DEFAULT, "refresh-token");
				ConfidentialClientFixture otherClient = createRefreshClient(TenantId.DEFAULT, "wrong-refresh-client")) {
			AuthorizationCodeFixture authorizationCode = authorize(user, client.client(), "openid profile");
			JsonNode initial = exchangeAuthorizationCode(client, authorizationCode);
			String initialAccessToken = initial.get("access_token").stringValue();
			String initialRefreshToken = initial.get("refresh_token").stringValue();
			String initialIdToken = initial.get("id_token").stringValue();
			assertThat(scopes(initial)).containsExactlyInAnyOrder("openid", "profile");
			assertThat(tokenCount(client.client())).isEqualTo(4);
			assertThat(tokenInvalidated(client.client(), "authorization_code")).isTrue();
			assertThat(tokenInvalidated(client.client(), "access_token")).isFalse();
			assertThat(tokenInvalidated(client.client(), "refresh_token")).isFalse();
			assertThat(tokenInvalidated(client.client(), "id_token")).isFalse();

			long revisionBeforeRefresh = authorizationRevision(client.client());
			UUID accessTokenId = tokenId(client.client(), "access_token");
			UUID refreshTokenId = tokenId(client.client(), "refresh_token");
			UUID idTokenId = tokenId(client.client(), "id_token");

			MvcResult invalidScope = this.mockMvc
				.perform(refreshRequest(client, initialRefreshToken, "openid email"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(invalidScope, "invalid_scope");
			MvcResult wrongClient = this.mockMvc
				.perform(refreshRequest(otherClient, initialRefreshToken, "openid"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(wrongClient, "invalid_grant");
			assertThat(authorizationRevision(client.client())).isEqualTo(revisionBeforeRefresh);
			assertThat(tokenId(client.client(), "access_token")).isEqualTo(accessTokenId);
			assertThat(tokenId(client.client(), "refresh_token")).isEqualTo(refreshTokenId);
			assertThat(tokenId(client.client(), "id_token")).isEqualTo(idTokenId);

			MvcResult refresh = this.mockMvc.perform(refreshRequest(client, initialRefreshToken, "openid"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andReturn();
			JsonNode rotated = JSON.readTree(refresh.getResponse().getContentAsString());
			String rotatedAccessToken = rotated.get("access_token").stringValue();
			String rotatedRefreshToken = rotated.get("refresh_token").stringValue();
			String rotatedIdToken = rotated.get("id_token").stringValue();
			assertThat(rotatedAccessToken).isNotEqualTo(initialAccessToken);
			assertThat(rotatedRefreshToken).isNotEqualTo(initialRefreshToken);
			assertThat(rotatedIdToken).isNotEqualTo(initialIdToken);
			assertThat(scopes(rotated)).containsExactly("openid");
			assertThat(this.jwtDecoder.decode(rotatedAccessToken).getClaimAsStringList("scope"))
				.containsExactly("openid");
			assertThat(tokenId(client.client(), "access_token")).isNotEqualTo(accessTokenId);
			assertThat(tokenId(client.client(), "refresh_token")).isNotEqualTo(refreshTokenId);
			assertThat(tokenId(client.client(), "id_token")).isNotEqualTo(idTokenId);
			assertThat(tokenCount(client.client())).isEqualTo(4);
			assertThat(accessTokenScopeCount(client.client())).isOne();
			assertThat(authorizationRevision(client.client())).isEqualTo(revisionBeforeRefresh + 1);

			long revisionAfterRefresh = authorizationRevision(client.client());
			UUID rotatedAccessTokenId = tokenId(client.client(), "access_token");
			UUID rotatedRefreshTokenId = tokenId(client.client(), "refresh_token");
			UUID rotatedIdTokenId = tokenId(client.client(), "id_token");
			MvcResult replay = this.mockMvc.perform(refreshRequest(client, initialRefreshToken, "openid"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(replay, "invalid_grant");
			assertThat(authorizationRevision(client.client())).isEqualTo(revisionAfterRefresh);
			assertThat(tokenId(client.client(), "access_token")).isEqualTo(rotatedAccessTokenId);
			assertThat(tokenId(client.client(), "refresh_token")).isEqualTo(rotatedRefreshTokenId);
			assertThat(tokenId(client.client(), "id_token")).isEqualTo(rotatedIdTokenId);

			MvcResult continuedRefresh = this.mockMvc.perform(refreshRequest(client, rotatedRefreshToken, null))
				.andExpect(status().isOk())
				.andReturn();
			JsonNode continued = JSON.readTree(continuedRefresh.getResponse().getContentAsString());
			assertThat(continued.get("access_token").stringValue()).isNotEqualTo(rotatedAccessToken);
			assertThat(continued.get("refresh_token").stringValue()).isNotEqualTo(rotatedRefreshToken);
			assertThat(continued.get("id_token").stringValue()).isNotEqualTo(rotatedIdToken);
			assertThat(scopes(continued)).containsExactlyInAnyOrder("openid", "profile");
			assertThat(authorizationRevision(client.client())).isEqualTo(revisionAfterRefresh + 1);
		}
	}

	@Test
	void allowsOnlyOneConcurrentRefreshRotation() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "concurrent-refresh");
		try (ConfidentialClientFixture client = createRefreshClient(TenantId.DEFAULT, "concurrent-refresh")) {
			AuthorizationCodeFixture authorizationCode = authorize(user, client.client(), "openid profile");
			String refreshToken = exchangeAuthorizationCode(client, authorizationCode).get("refresh_token").stringValue();
			long revision = authorizationRevision(client.client());
			UUID accessTokenId = tokenId(client.client(), "access_token");
			UUID refreshTokenId = tokenId(client.client(), "refresh_token");
			UUID idTokenId = tokenId(client.client(), "id_token");
			CountDownLatch ready = new CountDownLatch(2);
			CountDownLatch start = new CountDownLatch(1);
			List<Future<MvcResult>> pending = new ArrayList<>();
			List<MvcResult> results = new ArrayList<>();

			try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
				for (int index = 0; index < 2; index++) {
					pending.add(executor.submit(() -> {
						ready.countDown();
						start.await();
						return this.mockMvc.perform(refreshRequest(client, refreshToken, "openid")).andReturn();
					}));
				}
				boolean bothReady;
				try {
					bothReady = ready.await(5, TimeUnit.SECONDS);
				}
				finally {
					start.countDown();
				}
				assertThat(bothReady).isTrue();
				for (Future<MvcResult> result : pending) {
					results.add(result.get(15, TimeUnit.SECONDS));
				}
			}
			assertThat(results).extracting(result -> result.getResponse().getStatus())
				.containsExactlyInAnyOrder(200, 400);
			MvcResult rejected = results.stream()
				.filter(result -> result.getResponse().getStatus() == 400)
				.findFirst()
				.orElseThrow();
			assertOAuthError(rejected, "invalid_grant");
			assertThat(authorizationRevision(client.client())).isEqualTo(revision + 1);
			assertThat(tokenId(client.client(), "access_token")).isNotEqualTo(accessTokenId);
			assertThat(tokenId(client.client(), "refresh_token")).isNotEqualTo(refreshTokenId);
			assertThat(tokenId(client.client(), "id_token")).isNotEqualTo(idTokenId);
			assertThat(tokenCount(client.client())).isEqualTo(4);
		}
	}

	@Test
	void rejectsRefreshAfterTheAuthorizationSessionIsRevoked() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "revoked-refresh-session");
		try (ConfidentialClientFixture client = createRefreshClient(TenantId.DEFAULT, "revoked-refresh-session")) {
			AuthorizationCodeFixture authorizationCode = authorize(user, client.client(), "openid profile");
			String refreshToken = exchangeAuthorizationCode(client, authorizationCode).get("refresh_token").stringValue();
			long revision = authorizationRevision(client.client());
			SessionId sessionId = new SessionId(this.jdbcClient.sql("""
					SELECT session_id
					FROM oauth_authorizations
					WHERE client_id = :clientId
					""")
				.param("clientId", client.client().id().value())
				.query(UUID.class)
				.single());

			this.sessions.revoke(TenantId.DEFAULT, sessionId);

			MvcResult rejected = this.mockMvc.perform(refreshRequest(client, refreshToken, "openid"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(rejected, "invalid_grant");
			assertThat(authorizationRevision(client.client())).isEqualTo(revision);
		}
	}

	@Test
	void rejectsInvalidatedAndExpiredRefreshTokens() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "inactive-refresh");
		try (ConfidentialClientFixture client = createRefreshClient(TenantId.DEFAULT, "inactive-refresh")) {
			AuthorizationCodeFixture authorizationCode = authorize(user, client.client(), "openid profile");
			String refreshToken = exchangeAuthorizationCode(client, authorizationCode).get("refresh_token").stringValue();
			long revision = authorizationRevision(client.client());
			UUID refreshTokenId = tokenId(client.client(), "refresh_token");

			this.jdbcClient.sql("""
					UPDATE oauth_authorization_tokens
					SET invalidated_at = now(), updated_at = now(), version = version + 1
					WHERE token_id = :tokenId
					""")
				.param("tokenId", refreshTokenId)
				.update();
			MvcResult invalidated = this.mockMvc.perform(refreshRequest(client, refreshToken, null))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(invalidated, "invalid_grant");

			this.jdbcClient.sql("""
					UPDATE oauth_authorization_tokens
					SET invalidated_at = NULL, expires_at = issued_at + interval '1 microsecond',
					    updated_at = now(), version = version + 1
					WHERE token_id = :tokenId
					""")
				.param("tokenId", refreshTokenId)
				.update();
			MvcResult expired = this.mockMvc.perform(refreshRequest(client, refreshToken, null))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(expired, "invalid_grant");
			assertThat(authorizationRevision(client.client())).isEqualTo(revision);
			assertThat(tokenId(client.client(), "refresh_token")).isEqualTo(refreshTokenId);
		}
	}

	@Test
	void escapesUntrustedScopeValuesOnTheConsentPage() throws Exception {
		String untrustedScope = "read</label><script>alert(1)</script>";
		UserFixture user = createUser(TenantId.DEFAULT, "consent-escaping");
		OAuthClient client = createClient(TenantId.DEFAULT, "consent-escaping",
				Set.of(new ClientScope("openid"), new ClientScope(untrustedScope)));
		MockHttpSession session = beginAuthorization(client, "openid " + untrustedScope, "escape-state",
				"A".repeat(43), null);
		MvcResult login = this.mockMvc
			.perform(post("/login").session(session).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andReturn();
		MockHttpSession authenticatedSession = (MockHttpSession) login.getRequest().getSession(false);
		URI continuation = URI.create(login.getResponse().getHeader("Location"));
		MvcResult consentRedirect = this.mockMvc
			.perform(get(continuation).session(authenticatedSession).accept(MediaType.TEXT_HTML))
			.andExpect(status().isFound())
			.andReturn();
		String page = this.mockMvc
			.perform(get(URI.create(consentRedirect.getResponse().getHeader("Location"))).session(authenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();

		assertThat(page).contains("read&lt;/label&gt;&lt;script&gt;alert(1)&lt;/script&gt;")
			.doesNotContain(untrustedScope, "<script>");
	}

	@Test
	void deniesAdditionalScopesWithoutRevokingExistingConsent() throws Exception {
		UserFixture user = createUser(TenantId.DEFAULT, "consent-denial");
		OAuthClient client = createClient(TenantId.DEFAULT, "consent-denial",
				Set.of(new ClientScope("openid"), new ClientScope("profile"), new ClientScope("email")));
		MockHttpSession firstLoginSession = beginAuthorization(client, "openid profile", "approved-state",
				"A".repeat(43), null);
		MvcResult firstLogin = this.mockMvc
			.perform(post("/login").session(firstLoginSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andReturn();
		MockHttpSession firstAuthenticatedSession = (MockHttpSession) firstLogin.getRequest().getSession(false);
		MvcResult firstConsentRedirect = this.mockMvc
			.perform(get(URI.create(firstLogin.getResponse().getHeader("Location"))).session(firstAuthenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isFound())
			.andReturn();
		String firstConsentPage = this.mockMvc
			.perform(get(URI.create(firstConsentRedirect.getResponse().getHeader("Location")))
				.session(firstAuthenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString();
		this.mockMvc
			.perform(post("/oauth2/authorize").session(firstAuthenticatedSession)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
				.param(OAuth2ParameterNames.STATE, consentState(firstConsentPage))
				.param(OAuth2ParameterNames.SCOPE, "profile"))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith(REDIRECT_URI + "?")));
		assertThat(consentAuthorities(client)).containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_profile");
		assertThat(authorizationCount(client)).isOne();

		String deniedClientState = "denied-state-" + suffix();
		MockHttpSession secondLoginSession = beginAuthorization(client, "openid profile email", deniedClientState,
				"B".repeat(43), null);
		MvcResult secondLogin = this.mockMvc
			.perform(post("/login").session(secondLoginSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andReturn();
		MockHttpSession secondAuthenticatedSession = (MockHttpSession) secondLogin.getRequest().getSession(false);
		MvcResult secondConsentRedirect = this.mockMvc
			.perform(get(URI.create(secondLogin.getResponse().getHeader("Location"))).session(secondAuthenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isFound())
			.andReturn();
		String secondConsentPage = this.mockMvc
			.perform(get(URI.create(secondConsentRedirect.getResponse().getHeader("Location")))
				.session(secondAuthenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Already approved")))
			.andExpect(content().string(containsString("name=\"scope\" value=\"email\"")))
			.andReturn()
			.getResponse()
			.getContentAsString();
		assertThat(authorizationCount(client)).isEqualTo(2);
		String secondConsentState = consentState(secondConsentPage);
		this.mockMvc
			.perform(post(AuthorizationConsentController.DENIAL_PATH).session(secondAuthenticatedSession)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
				.param(OAuth2ParameterNames.STATE, secondConsentState))
			.andExpect(status().isForbidden());
		assertThat(authorizationCount(client)).isEqualTo(2);

		MvcResult denial = this.mockMvc
			.perform(post(AuthorizationConsentController.DENIAL_PATH).session(secondAuthenticatedSession)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
				.param(OAuth2ParameterNames.STATE, secondConsentState)
				.param("_csrf", csrfToken(secondConsentPage)))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith(REDIRECT_URI + "?")))
			.andReturn();
		URI denialRedirect = URI.create(denial.getResponse().getHeader("Location"));
		assertThat(queryParameter(denialRedirect, OAuth2ParameterNames.ERROR)).isEqualTo("access_denied");
		assertThat(queryParameter(denialRedirect, OAuth2ParameterNames.STATE)).isEqualTo(deniedClientState);
		assertThat(authorizationCount(client)).isOne();
		assertThat(consentAuthorities(client)).containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_profile");
	}

	@Test
	void issuesTenantBoundClientCredentialsAccessTokens() throws Exception {
		try (ConfidentialClientFixture client = createServiceClient(TenantId.DEFAULT, "service-token")) {
			MvcResult result = this.mockMvc.perform(clientCredentialsRequest(client, "scim.read")
				.param("tenant_id", UUID.randomUUID().toString())
				.param("audience", "https://attacker.example.test"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andReturn();
			JsonNode response = JSON.readTree(result.getResponse().getContentAsString());
			assertThat(response.get("token_type").stringValue()).isEqualTo("Bearer");
			assertThat(response.get("scope").stringValue()).isEqualTo("scim.read");
			assertThat(response.hasNonNull("refresh_token")).isFalse();
			assertThat(response.hasNonNull("id_token")).isFalse();

			Jwt accessToken = this.jwtDecoder.decode(response.get("access_token").stringValue());
			assertThat(accessToken.getIssuer().toString()).isEqualTo(ISSUER);
			assertThat(accessToken.getSubject()).isEqualTo(client.client().identifier().value());
			assertThat(accessToken.getAudience()).containsExactly("https://scim.example.test/scim/v2");
			assertThat(accessToken.getClaimAsString(ServiceTokenJwtCustomizer.TENANT_ID_CLAIM))
				.isEqualTo(TenantId.DEFAULT.toString());
			assertThat(accessToken.getClaimAsString(ServiceTokenJwtCustomizer.CLIENT_ID_CLAIM))
				.isEqualTo(client.client().identifier().value());
			assertThat(accessToken.getClaimAsStringList(OAuth2ParameterNames.SCOPE)).containsExactly("scim.read");
			assertThat(serviceAuthorizationShape(client.client())).isTrue();
			assertThat(authorizationCount(client.client())).isOne();
			assertThat(tokenCount(client.client())).isOne();
			assertThat(accessTokenScopeCount(client.client())).isOne();
		}
	}

	@Test
	void acceptsOfficialUnscopedClientCredentialsRequestsWithoutGrantingScopes() throws Exception {
		try (ConfidentialClientFixture client = createServiceClient(TenantId.DEFAULT, "unscoped-service-token")) {
			MvcResult result = this.mockMvc.perform(clientCredentialsRequest(client, null))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andReturn();
			JsonNode response = JSON.readTree(result.getResponse().getContentAsString());
			assertThat(response.hasNonNull("scope")).isFalse();
			Jwt accessToken = this.jwtDecoder.decode(response.get("access_token").stringValue());
			List<String> scopes = accessToken.getClaimAsStringList(OAuth2ParameterNames.SCOPE);
			assertThat(scopes == null ? List.of() : scopes).isEmpty();
			assertThat(authorizationScopes(client.client())).isEmpty();
			assertThat(accessTokenScopeCount(client.client())).isZero();
			assertThat(serviceAuthorizationShape(client.client())).isTrue();
		}
	}

	@Test
	void rejectsInvalidClientCredentialsRequestsWithoutPersistingAuthorizations() throws Exception {
		try (ConfidentialClientFixture service = createServiceClient(TenantId.DEFAULT, "invalid-service-token");
				ConfidentialClientFixture browser = createRefreshClient(TenantId.DEFAULT, "wrong-service-grant")) {
			MvcResult wrongSecret = this.mockMvc.perform(post("/oauth2/token")
				.with(httpBasic(service.client().identifier().value(), "wrong-secret"))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
				.andExpect(status().isUnauthorized())
				.andReturn();
			assertOAuthError(wrongSecret, "invalid_client");

			MvcResult wrongGrant = this.mockMvc.perform(clientCredentialsRequest(browser, "openid"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(wrongGrant, "unauthorized_client");

			MvcResult invalidScope = this.mockMvc.perform(clientCredentialsRequest(service, "unregistered"))
				.andExpect(status().isBadRequest())
				.andReturn();
			assertOAuthError(invalidScope, "invalid_scope");
			assertThat(authorizationCount(service.client())).isZero();
			assertThat(authorizationCount(browser.client())).isZero();
		}
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

	private ConfidentialClientFixture createRefreshClient(TenantId tenantId, String purpose) {
		String identifier = "login-" + purpose + "-" + suffix();
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier(identifier),
				"Authorization Refresh Client", ClientType.CONFIDENTIAL,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, Set.of(new ClientRedirectUri(REDIRECT_URI)), Set.of(),
				Set.of(new ClientScope("openid"), new ClientScope("profile")),
				ClientTokenPolicy.refreshEnabledDefaults());
		try (ClientRegistration registration = this.clients.create(tenantId, request)) {
			this.clientsToDelete.add(registration.client().id());
			return new ConfidentialClientFixture(registration.client(), registration.clientSecret().orElseThrow().copy());
		}
	}

	private ConfidentialClientFixture createServiceClient(TenantId tenantId, String purpose) {
		String identifier = "service-" + purpose + "-" + suffix();
		CreateClientRequest request = new CreateClientRequest(new ClientIdentifier(identifier),
				"SCIM Service Client", ClientType.CONFIDENTIAL, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				ClientAuthorizationGrant.CLIENT_CREDENTIALS, Set.of(), Set.of(),
				Set.of(new ClientScope("scim.read"), new ClientScope("scim.write")),
				ClientTokenPolicy.serviceDefaults());
		try (ClientRegistration registration = this.clients.create(tenantId, request)) {
			this.clientsToDelete.add(registration.client().id());
			return new ConfidentialClientFixture(registration.client(), registration.clientSecret().orElseThrow().copy());
		}
	}

	private AuthorizationCodeFixture authorize(UserFixture user, OAuthClient client, String scopes) throws Exception {
		String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
		String challenge = pkceChallenge(verifier);
		String state = "refresh-state-" + suffix();
		MockHttpSession loginSession = beginAuthorization(client, scopes, state, challenge, "refresh-nonce-" + suffix());
		MvcResult login = this.mockMvc
			.perform(post("/login").session(loginSession).with(csrf()).param("username", user.username())
				.param("password", PASSWORD))
			.andExpect(status().isFound())
			.andExpect(authenticated())
			.andReturn();
		MockHttpSession authenticatedSession = (MockHttpSession) login.getRequest().getSession(false);
		MvcResult consentRedirect = this.mockMvc
			.perform(get(URI.create(login.getResponse().getHeader("Location"))).session(authenticatedSession)
				.accept(MediaType.TEXT_HTML))
			.andExpect(status().isFound())
			.andReturn();
		URI consentUri = URI.create(consentRedirect.getResponse().getHeader("Location"));
		MvcResult consentPage = this.mockMvc.perform(get(consentUri).session(authenticatedSession).accept(MediaType.TEXT_HTML))
			.andExpect(status().isOk())
			.andReturn();
		MvcResult consent = this.mockMvc
			.perform(post("/oauth2/authorize").session(authenticatedSession)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param(OAuth2ParameterNames.CLIENT_ID, client.identifier().value())
				.param(OAuth2ParameterNames.STATE,
						consentState(consentPage.getResponse().getContentAsString()))
				.param(OAuth2ParameterNames.SCOPE, "profile"))
			.andExpect(status().isFound())
			.andExpect(header().string("Location", startsWith(REDIRECT_URI + "?")))
			.andReturn();
		URI clientRedirect = URI.create(consent.getResponse().getHeader("Location"));
		assertThat(queryParameter(clientRedirect, OAuth2ParameterNames.STATE)).isEqualTo(state);
		return new AuthorizationCodeFixture(queryParameter(clientRedirect, OAuth2ParameterNames.CODE), verifier);
	}

	private JsonNode exchangeAuthorizationCode(ConfidentialClientFixture client,
			AuthorizationCodeFixture authorizationCode) throws Exception {
		MvcResult result = this.mockMvc.perform(authorizationCodeTokenRequest(client, authorizationCode))
			.andExpect(status().isOk())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andReturn();
		JsonNode response = JSON.readTree(result.getResponse().getContentAsString());
		assertThat(response.get("token_type").stringValue()).isEqualTo("Bearer");
		assertThat(response.get("expires_in").longValue()).isPositive();
		assertThat(response.hasNonNull("access_token")).isTrue();
		assertThat(response.hasNonNull("refresh_token")).isTrue();
		assertThat(response.hasNonNull("id_token")).isTrue();
		return response;
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

	private UUID tokenId(OAuthClient client, String tokenType) {
		return this.jdbcClient.sql("""
				SELECT token_id
				FROM oauth_authorization_tokens
				WHERE client_id = :clientId AND token_type = :tokenType
				""")
			.param("clientId", client.id().value())
			.param("tokenType", tokenType)
			.query(UUID.class)
			.single();
	}

	private int authorizationCount(OAuthClient client) {
		return count("SELECT count(*) FROM oauth_authorizations WHERE client_id = :clientId", client);
	}

	private boolean serviceAuthorizationShape(OAuthClient client) {
		return this.jdbcClient.sql("""
				SELECT authorization_grant_type = 'client_credentials'
				   AND principal_name = client_identifier
				   AND user_id IS NULL
				   AND session_id IS NULL
				   AND authorization_uri IS NULL
				   AND redirect_uri IS NULL
				   AND client_state IS NULL
				   AND request_parameters = '{}'::jsonb
				FROM oauth_authorizations
				WHERE client_id = :clientId
				""")
			.param("clientId", client.id().value())
			.query(Boolean.class)
			.single();
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

	private static MockHttpServletRequestBuilder authorizationCodeTokenRequest(ConfidentialClientFixture client,
			AuthorizationCodeFixture authorizationCode) {
		return post("/oauth2/token").with(httpBasic(client.client().identifier().value(), client.secretValue()))
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
			.param(OAuth2ParameterNames.CODE, authorizationCode.code())
			.param(OAuth2ParameterNames.REDIRECT_URI, REDIRECT_URI)
			.param(PkceParameterNames.CODE_VERIFIER, authorizationCode.verifier());
	}

	private static MockHttpServletRequestBuilder refreshRequest(ConfidentialClientFixture client, String refreshToken,
			String scope) {
		MockHttpServletRequestBuilder request = post("/oauth2/token")
			.with(httpBasic(client.client().identifier().value(), client.secretValue()))
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
			.param(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
		return scope == null ? request : request.param(OAuth2ParameterNames.SCOPE, scope);
	}

	private static MockHttpServletRequestBuilder clientCredentialsRequest(ConfidentialClientFixture client,
			String scope) {
		MockHttpServletRequestBuilder request = post("/oauth2/token")
			.with(httpBasic(client.client().identifier().value(), client.secretValue()))
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		return scope == null ? request : request.param(OAuth2ParameterNames.SCOPE, scope);
	}

	private static Set<String> scopes(JsonNode response) {
		return Set.copyOf(List.of(response.get("scope").stringValue().split(" ")));
	}

	private static void assertOAuthError(MvcResult result, String expected) throws Exception {
		assertThat(JSON.readTree(result.getResponse().getContentAsString()).get("error").stringValue())
			.isEqualTo(expected);
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

	private static String csrfToken(String page) {
		Matcher matcher = CSRF_TOKEN.matcher(page);
		assertThat(matcher.find()).as("CSRF token field").isTrue();
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

	private record AuthorizationCodeFixture(String code, String verifier) {
	}

	private record ConfidentialClientFixture(OAuthClient client, char[] clientSecret) implements AutoCloseable {

		private String secretValue() {
			return new String(this.clientSecret);
		}

		@Override
		public void close() {
			Arrays.fill(this.clientSecret, '\0');
		}

	}

}
