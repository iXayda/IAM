package com.ixayda.iam.client;

import java.util.Set;

public record CreateClientRequest(ClientIdentifier identifier, String displayName, ClientType type,
		ClientAuthenticationMethod authenticationMethod, Set<ClientRedirectUri> redirectUris,
		Set<ClientRedirectUri> postLogoutRedirectUris, Set<ClientScope> scopes, ClientTokenPolicy tokenPolicy) {

	public CreateClientRequest {
		displayName = OAuthClient.normalizeDisplayName(displayName);
		OAuthClient.validateAuthentication(identifier, type, authenticationMethod);
		redirectUris = OAuthClient.requiredCopy(redirectUris, "Client redirect URIs",
				OAuthClient.MAX_REDIRECT_URI_COUNT);
		postLogoutRedirectUris = OAuthClient.optionalCopy(postLogoutRedirectUris,
				"Client post-logout redirect URIs", OAuthClient.MAX_REDIRECT_URI_COUNT);
		scopes = OAuthClient.requiredCopy(scopes, "Client scopes", OAuthClient.MAX_SCOPE_COUNT);
		OAuthClient.validateScopes(postLogoutRedirectUris, scopes);
		OAuthClient.requireTokenPolicy(tokenPolicy);
	}

}
