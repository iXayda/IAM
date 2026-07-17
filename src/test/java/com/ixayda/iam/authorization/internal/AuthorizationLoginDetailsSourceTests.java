package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;

import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

class AuthorizationLoginDetailsSourceTests {

	private final ClientOperations clients = mock(ClientOperations.class);

	private final AuthorizationLoginDetailsSource detailsSource = new AuthorizationLoginDetailsSource(this.clients);

	@Test
	void resolvesTheTenantFromAnActiveSavedAuthorizationClient() {
		ClientIdentifier identifier = new ClientIdentifier("saved-request-client");
		OAuthClient client = mock(OAuthClient.class);
		when(client.tenantId()).thenReturn(TenantId.DEFAULT);
		when(this.clients.findActiveByIdentifier(identifier)).thenReturn(Optional.of(client));
		MockHttpServletRequest login = loginRequest(savedAuthorizationRequest(identifier.value()));
		login.setRemoteAddr("203.0.113.8");

		AuthorizationLoginDetails details = this.detailsSource.buildDetails(login);

		assertThat(details.tenantId()).contains(TenantId.DEFAULT);
		assertThat(details.source().value()).isEqualTo("remote:203.0.113.8");
	}

	@Test
	void leavesTheTenantUnresolvedWithoutAValidSavedAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		request.setRemoteAddr("invalid address");

		AuthorizationLoginDetails details = this.detailsSource.buildDetails(request);

		assertThat(details.tenantId()).isEmpty();
		assertThat(details.source().value()).isEqualTo("remote:unknown");
		verifyNoInteractions(this.clients);
	}

	@Test
	void leavesTheTenantUnresolvedForInactiveOrMalformedClients() {
		ClientIdentifier inactive = new ClientIdentifier("inactive-client");
		when(this.clients.findActiveByIdentifier(inactive)).thenReturn(Optional.empty());

		AuthorizationLoginDetails inactiveDetails =
				this.detailsSource.buildDetails(loginRequest(savedAuthorizationRequest(inactive.value())));
		AuthorizationLoginDetails malformedDetails =
				this.detailsSource.buildDetails(loginRequest(savedAuthorizationRequest("?")));

		assertThat(inactiveDetails.tenantId()).isEmpty();
		assertThat(malformedDetails.tenantId()).isEmpty();
	}

	@Test
	void leavesTheTenantUnresolvedForNonGetOrRepeatedClientParameters() {
		MockHttpServletRequest postAuthorization = new MockHttpServletRequest("POST", "/oauth2/authorize");
		postAuthorization.addParameter(OAuth2ParameterNames.CLIENT_ID, "saved-request-client");
		MockHttpServletRequest repeatedClient = new MockHttpServletRequest("GET", "/oauth2/authorize");
		repeatedClient.addParameter(OAuth2ParameterNames.CLIENT_ID, "saved-request-client", "second-client");

		AuthorizationLoginDetails postDetails = this.detailsSource
			.buildDetails(loginRequest(new DefaultSavedRequest(postAuthorization, "continue")));
		AuthorizationLoginDetails repeatedDetails = this.detailsSource
			.buildDetails(loginRequest(new DefaultSavedRequest(repeatedClient, "continue")));

		assertThat(postDetails.tenantId()).isEmpty();
		assertThat(repeatedDetails.tenantId()).isEmpty();
		verifyNoInteractions(this.clients);
	}

	private static DefaultSavedRequest savedAuthorizationRequest(String clientIdentifier) {
		MockHttpServletRequest authorization = new MockHttpServletRequest("GET", "/oauth2/authorize");
		authorization.addParameter(OAuth2ParameterNames.CLIENT_ID, clientIdentifier);
		return new DefaultSavedRequest(authorization, "continue");
	}

	private static MockHttpServletRequest loginRequest(DefaultSavedRequest savedRequest) {
		MockHttpServletRequest login = new MockHttpServletRequest("POST", "/login");
		MockHttpSession session = new MockHttpSession();
		session.setAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE, savedRequest);
		login.setSession(session);
		return login;
	}

}
