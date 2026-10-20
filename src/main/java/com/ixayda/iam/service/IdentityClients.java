package com.ixayda.iam.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import com.ixayda.iam.credential.ClientSecrets;
import com.ixayda.iam.model.IdentityClient;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.IdentityClientPage;
import com.ixayda.iam.model.IdentityClientSecret;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourceRole;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.SecurityAuditEvent.Action;
import com.ixayda.iam.model.SecurityAuditTarget;
import com.ixayda.iam.repository.IdentityClientRepository;
import com.ixayda.iam.repository.IdentityResourceRoleRepository;

import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

/** Trusted client registration workflow; callers authorize operations and control one-time secret delivery. */
@Service
public class IdentityClients {

	private final IdentityClientRepository repository;
	private final IdentityResources resources;
	private final IdentityResourceRoleRepository roles;
	private final ClientSecrets secrets;
	private final SecurityAudits audits;

	IdentityClients(IdentityClientRepository repository, IdentityResources resources, IdentityResourceRoleRepository roles,
			ClientSecrets secrets, SecurityAudits audits) {
		this.repository = repository;
		this.resources = resources;
		this.roles = roles;
		this.secrets = secrets;
		this.audits = audits;
	}

	@Transactional
	public IdentityClientSecret create(IdentityClientConfiguration configuration, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var config = normalize(configuration);
		var resource = this.resources.lockById(config.resourceId()).orElseThrow(() -> new NoSuchElementException("Resource not found"));
		requireActive(resource);
		lockRoles(config, null, resource);
		UUID id = UUID.randomUUID();
		String secret = this.secrets.generate();
		var client = this.repository.create(build(id, config, this.secrets.hash(secret), this.repository.databaseTime()), config.resourceId(), config.allowedRoleIds());
		record(Action.CLIENT_CREATED, id, audit);
		return new IdentityClientSecret(client, secret);
	}

	public Optional<IdentityClient> findById(UUID id) {
		Assert.notNull(id, "Client id is required");
		return this.repository.findById(id);
	}

	public IdentityClientPage search(IdentityClient.Status status, int pageSize, IdentityClientPage.Cursor after) {
		if (pageSize < 1 || pageSize > 100) { throw new IllegalArgumentException("Page size must be between 1 and 100"); }
		if (after != null && after.status() != status) { throw new IllegalArgumentException("Cursor client status must match"); }
		var rows = this.repository.search(status, pageSize + 1, after);
		boolean more = rows.size() > pageSize;
		var items = more ? rows.subList(0, pageSize) : rows;
		var last = more ? items.getLast() : null;
		return new IdentityClientPage(items, more ? new IdentityClientPage.Cursor(last.createdAt(), last.id(), status) : null);
	}

	@Transactional
	public IdentityClient updateConfiguration(UUID id, long expectedVersion, IdentityClientConfiguration configuration, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var config = normalize(configuration);
		var locked = lockCurrent(id, expectedVersion, config);
		var current = locked.client();
		if (current.configuration().equals(config)) { return current; }
		var previous = registered(current);
		var changed = this.repository.update(current, build(id, config, previous.getClientSecret(), previous.getClientIdIssuedAt()),
				config.resourceId(), config.allowedRoleIds(), current.status(), false);
		record(Action.CLIENT_UPDATED, id, audit);
		return changed;
	}

	@Transactional
	public IdentityClient setEnabled(UUID id, long expectedVersion, boolean enabled, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var locked = lockCurrent(id, expectedVersion, null);
		if (enabled) { requireActive(locked.resource()); }
		var current = locked.client();
		var next = enabled ? IdentityClient.Status.ACTIVE : IdentityClient.Status.DISABLED;
		if (current.status() == next) { return current; }
		var changed = this.repository.update(current, registered(current), current.configuration().resourceId(), current.configuration().allowedRoleIds(), next, false);
		record(enabled ? Action.CLIENT_ENABLED : Action.CLIENT_DISABLED, id, audit);
		return changed;
	}

	@Transactional
	public IdentityClientSecret rotateSecret(UUID id, long expectedVersion, SecurityAuditContext audit) {
		Assert.notNull(audit, "Audit context is required");
		var current = lockCurrent(id, expectedVersion, null).client();
		String secret = this.secrets.generate();
		var client = RegisteredClient.from(registered(current)).clientSecret(this.secrets.hash(secret)).build();
		var changed = this.repository.update(current, client, current.configuration().resourceId(), current.configuration().allowedRoleIds(), current.status(), true);
		record(Action.CLIENT_SECRET_ROTATED, id, audit);
		return new IdentityClientSecret(changed, secret);
	}

	private LockedClient lockCurrent(UUID id, long expectedVersion, IdentityClientConfiguration replacement) {
		Assert.notNull(id, "Client id is required");
		if (expectedVersion < 1) { throw new IllegalArgumentException("Client version must be positive"); }
		var hint = this.repository.findById(id).orElseThrow(() -> new NoSuchElementException("Client not found"));
		UUID nextResource = replacement == null ? hint.configuration().resourceId() : replacement.resourceId();
		var parents = new TreeSet<>(Set.of(hint.configuration().resourceId()));
		parents.add(nextResource);
		IdentityResource targetResource = null;
		for (UUID resourceId : parents) {
			var resource = this.resources.lockById(resourceId).orElseThrow(() -> new NoSuchElementException("Resource not found"));
			if (resourceId.equals(nextResource)) { targetResource = resource; }
		}
		// Parent changes during the hint read must never lead to modifying a client without its actual parent lock.
		var current = this.repository.findById(id).orElseThrow(() -> new NoSuchElementException("Client not found"));
		requireVersion(current, hint, expectedVersion);
		if (replacement != null) { lockRoles(replacement, current.configuration(), targetResource); }
		current = this.repository.lockById(id).orElseThrow(() -> new NoSuchElementException("Client not found"));
		requireVersion(current, hint, expectedVersion);
		return new LockedClient(current, targetResource);
	}

	private static void requireVersion(IdentityClient current, IdentityClient hint, long expectedVersion) {
		if (current.version() != expectedVersion || !current.configuration().resourceId().equals(hint.configuration().resourceId())) {
			throw new OptimisticLockingFailureException("Client version is stale");
		}
	}

	private void lockRoles(IdentityClientConfiguration config, IdentityClientConfiguration previous, IdentityResource resource) {
		for (UUID roleId : config.allowedRoleIds().stream().sorted().toList()) {
			var hint = this.roles.findById(roleId).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
			if (!hint.resourceId().equals(config.resourceId())) { throw new ClientConfigurationNotAllowedException(); }
			var role = this.roles.lockById(roleId).orElseThrow(() -> new NoSuchElementException("Resource role not found"));
			if (!role.resourceId().equals(config.resourceId())) { throw new ClientConfigurationNotAllowedException(); }
			boolean added = previous == null || !previous.resourceId().equals(config.resourceId()) || !previous.allowedRoleIds().contains(roleId);
			if (added && (resource.status() != IdentityResource.Status.ACTIVE || role.status() != IdentityResourceRole.Status.ACTIVE)) {
				throw new ClientConfigurationNotAllowedException();
			}
		}
		if (previous != null && !previous.resourceId().equals(config.resourceId())) { requireActive(resource); }
	}

	private RegisteredClient registered(IdentityClient client) {
		var registered = this.repository.registeredById(client.id());
		if (registered == null) { throw new IllegalStateException("Protocol client is missing"); }
		return registered;
	}

	private void record(Action action, UUID id, SecurityAuditContext audit) { this.audits.recordTargetSuccess(action, new SecurityAuditTarget(SecurityAuditTarget.Type.CLIENT, id), audit); }
	private static void requireActive(IdentityResource resource) { if (resource.status() != IdentityResource.Status.ACTIVE) { throw new ClientConfigurationNotAllowedException(); } }

	static IdentityClientConfiguration normalize(IdentityClientConfiguration config) {
		Assert.notNull(config, "Client configuration is required");
		Assert.notNull(config.resourceId(), "Resource id is required");
		String display = IdentityDisplayNames.normalize(config.displayName(), "Client display name is invalid");
		var redirects = redirects(config.redirectUris());
		if (!config.scopes().contains("openid") || !Set.of("openid", "profile", "offline_access").containsAll(config.scopes())) {
			throw new IllegalArgumentException("Client scopes require openid and accept only openid, profile, offline_access");
		}
		if (config.allowedRoleIds().size() > 100) { throw new IllegalArgumentException("A client accepts at most 100 roles"); }
		return new IdentityClientConfiguration(display, config.resourceId(), redirects, config.scopes(), config.allowedRoleIds());
	}

	private static List<String> redirects(List<String> values) {
		if (values.isEmpty() || values.size() > 10 || values.stream().distinct().count() != values.size()
				|| String.join(",", values).length() > 1000) { throw new IllegalArgumentException("Invalid redirect list"); }
		for (String value : values) {
			if (value.isEmpty() || value.chars().anyMatch(c -> c < 0x21 || c > 0x7e || c == ',' || c == '*')) { throw new IllegalArgumentException("Invalid redirect URI"); }
			try {
				var uri = new URI(value);
				if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
						|| uri.getPort() == 0 || uri.getPort() > 65535 || uri.getPort() < -1
						|| uri.getRawAuthority().endsWith(":") || hasControls(uri.getPath()) || hasControls(uri.getQuery())) {
					throw new IllegalArgumentException("Exact HTTPS redirect URI is required");
				}
			}
			catch (URISyntaxException ex) { throw new IllegalArgumentException("Invalid redirect URI", ex); }
		}
		return values.stream().sorted().toList();
	}

	private static boolean hasControls(String value) { return value != null && value.codePoints().anyMatch(Character::isISOControl); }

	private static RegisteredClient build(UUID id, IdentityClientConfiguration config, String hash, Instant issuedAt) {
		var client = RegisteredClient.withId(id.toString()).clientId(id.toString()).clientIdIssuedAt(issuedAt).clientName(config.displayName())
				.clientSecret(hash).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
				.tokenSettings(TokenSettings.builder().authorizationCodeTimeToLive(Duration.ofSeconds(60)).accessTokenTimeToLive(Duration.ofSeconds(300))
						.refreshTokenTimeToLive(Duration.ofDays(7)).reuseRefreshTokens(false).idTokenSignatureAlgorithm(SignatureAlgorithm.RS256).build());
		if (config.scopes().contains("offline_access")) { client.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN); }
		config.redirectUris().forEach(client::redirectUri);
		config.scopes().stream().sorted().forEach(client::scope);
		return client.build();
	}

	private record LockedClient(IdentityClient client, IdentityResource resource) { }
	public static final class ClientConfigurationNotAllowedException extends IllegalStateException {
		ClientConfigurationNotAllowedException() { super("Client configuration requires matching roles and active new references"); }
	}

}
