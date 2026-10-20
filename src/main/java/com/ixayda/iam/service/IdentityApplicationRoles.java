package com.ixayda.iam.service;

import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityApplicationAccess;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.repository.IdentityUserRoleRepository;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Trusted application projection; no browser authentication or management authority becomes an application role. */
@Service
@Lazy
public class IdentityApplicationRoles {

	private final IdentitySigningKeys keys;
	private final IdentityUsers users;
	private final IdentityProtocolClients clients;
	private final IdentityUserRoleRepository bindings;

	IdentityApplicationRoles(IdentitySigningKeys keys, IdentityUsers users, IdentityProtocolClients clients, IdentityUserRoleRepository bindings) {
		this.keys = keys; this.users = users; this.clients = clients; this.bindings = bindings;
	}

	/** Call before any subject/catalog locks; the outer workflow retains all locks through grant and audit commit. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<IdentityApplicationAccess> projectForIssuance(UUID userId, long credentialVersion, IdentityProtocolClients.Snapshot client) {
		return project(userId, credentialVersion, client, false);
	}

	/** Browser requests may save the session in this transaction; acquire UPDATE up front, never upgrade SHARE. */
	@Transactional(propagation = Propagation.MANDATORY)
	Optional<IdentityApplicationAccess> projectForBrowserIssuance(UUID userId, long credentialVersion, IdentityProtocolClients.Snapshot client) {
		return project(userId, credentialVersion, client, true);
	}

	private Optional<IdentityApplicationAccess> project(UUID userId, long credentialVersion, IdentityProtocolClients.Snapshot client, boolean browser) {
		Assert.notNull(userId, "Subject is required"); Assert.notNull(client, "Client snapshot is required");
		if (credentialVersion < 1) { throw new IllegalArgumentException("Subject credential version must be positive"); }
		this.keys.lockForIssuance();
		var user = browser ? this.users.lockForStateChange(userId) : this.users.lockForAuthorization(userId);
		if (user.isEmpty() || user.orElseThrow().status() != IdentityUser.Status.ACTIVE || !this.users.passwordVersion(userId).equals(Optional.of(credentialVersion))) { return Optional.empty(); }
		var locked = this.clients.lockForIssuance(client);
		if (locked.isEmpty()) { return Optional.empty(); }
		var current = locked.orElseThrow();
		var roles = this.bindings.projectForClient(userId, current.resource().id(), current.client().id());
		return Optional.of(new IdentityApplicationAccess(userId, current.client().id(), current.resource().id(), current.resource().audience(), credentialVersion,
				current.client().version(), current.resource().version(), roles.version(), roles.roles()));
	}

}
