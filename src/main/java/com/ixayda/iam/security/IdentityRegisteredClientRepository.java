package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityProtocolClients;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/** Explicit framework adapter; registration writes always go through the audited management workflow. */
public final class IdentityRegisteredClientRepository implements RegisteredClientRepository {

	private final IdentityProtocolClients clients;

	public IdentityRegisteredClientRepository(IdentityProtocolClients clients) {
		Assert.notNull(clients, "Protocol clients are required");
		this.clients = clients;
	}

	@Override
	public void save(RegisteredClient registeredClient) { throw new UnsupportedOperationException("Client registration requires audited management"); }

	@Override
	public RegisteredClient findById(String id) { return find(id); }

	@Override
	public RegisteredClient findByClientId(String clientId) { return find(clientId); }

	private RegisteredClient find(String id) {
		try { return this.clients.findActiveById(id).map(IdentityProtocolClients.Snapshot::registration).orElse(null); }
		catch (RuntimeException ex) { throw new OAuth2AuthenticationException(new OAuth2Error("server_error", "Client registration is unavailable", null)); }
	}

}
