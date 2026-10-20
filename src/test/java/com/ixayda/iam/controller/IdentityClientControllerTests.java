package com.ixayda.iam.controller;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.dto.IdentityClientSecretResponse;
import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityBrowserSessions;
import com.ixayda.iam.service.IdentityClientManagement;
import com.ixayda.iam.service.IdentityClients;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityClientControllerTests {

	@ParameterizedTest
	@ValueSource(strings = { "", "/iam" })
	void creationLocationRetainsTheDeploymentContextPathAndSecretResponse(String contextPath) throws Exception {
		UUID actorId = UUID.randomUUID(); UUID clientId = UUID.randomUUID(); UUID resourceId = UUID.randomUUID();
		var configuration = new IdentityClientConfiguration("Orders app", resourceId, List.of("https://application.example/callback"), Set.of("openid"), Set.of());
		var client = new IdentityClient(clientId, configuration, IdentityClient.Status.ACTIVE, 1, Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
		String secret = "a".repeat(43);
		var management = mock(IdentityClientManagement.class);
		when(management.create(any(), eq(configuration), eq("123456"), any()))
				.thenReturn(new IdentityClientManagement.Result(IdentityClientManagement.Status.COMPLETED, client, secret));
		var controller = new IdentityClientController(mock(IdentityClients.class), management, mock(IdentityAdministratorSessions.class));
		var request = new MockHttpServletRequest("POST", contextPath + "/api/admin/clients");
		request.setContextPath(contextPath); request.setServletPath("/api/admin/clients"); request.setSecure(true);
		request.setRemoteAddr("127.0.0.1"); request.setContentType("application/json");
		request.setContent("""
				{"configuration":{"displayName":"Orders app","resourceId":"%s","redirectUris":["https://application.example/callback"],"scopes":["openid"],"allowedRoleIds":[]},"code":"123456"}
				""".formatted(resourceId).getBytes(StandardCharsets.UTF_8));
		var session = request.getSession();
		session.setAttribute(IdentityBrowserSessions.CREDENTIAL_VERSION, 1L);
		session.setAttribute(IdentityBrowserSessions.AUTHENTICATED_AT, 1L);
		session.setAttribute(IdentityAdministratorSessions.AUTHENTICATION,
				new IdentityAdministratorAuthentication(actorId, UUID.randomUUID(), 1, 1, Instant.EPOCH));

		var result = controller.create(actorId, request, new MockHttpServletResponse());

		assertThat(result.getStatusCode().value()).isEqualTo(201);
		assertThat(result.getHeaders().getLocation()).isEqualTo(URI.create(contextPath + "/api/admin/clients/" + clientId));
		assertThat(result.getBody()).isInstanceOfSatisfying(IdentityClientSecretResponse.class, body -> {
			assertThat(body.secret()).isEqualTo(secret);
			assertThat(body.client().id()).isEqualTo(clientId);
			assertThat(body.client().configuration().displayName()).isEqualTo(configuration.displayName());
			assertThat(body.client().configuration().resourceId()).isEqualTo(resourceId);
			assertThat(body.client().status()).isEqualTo(IdentityClient.Status.ACTIVE);
			assertThat(body.client().version()).isEqualTo(1);
		});
		verify(management).create(argThat(context -> context.actorId().equals(actorId) && context.sessionId().equals(session.getId())),
				eq(configuration), eq("123456"), any());
	}

}
