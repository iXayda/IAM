package com.ixayda.iam.client.internal;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

import com.ixayda.iam.client.ClientConcurrentUpdateException;
import com.ixayda.iam.client.ClientDisabledException;
import com.ixayda.iam.client.ClientId;
import com.ixayda.iam.client.ClientIdentifier;
import com.ixayda.iam.client.ClientNotFoundException;
import com.ixayda.iam.client.ClientOperations;
import com.ixayda.iam.client.ClientRegistration;
import com.ixayda.iam.client.ClientType;
import com.ixayda.iam.client.CreateClientRequest;
import com.ixayda.iam.client.IssuedClientSecret;
import com.ixayda.iam.client.OAuthClient;
import com.ixayda.iam.tenant.TenantDisabledException;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.tenant.TenantNotFoundException;
import com.ixayda.iam.tenant.TenantOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
class DefaultClientOperations implements ClientOperations {

	private final JdbcOAuthClientRepository repository;

	private final ClientWriter writer;

	private final TenantOperations tenants;

	private final ClientSecretHashing hashing;

	private final ClientTimeSource timeSource;

	DefaultClientOperations(JdbcOAuthClientRepository repository, ClientWriter writer, TenantOperations tenants,
			ClientSecretHashing hashing, ClientTimeSource timeSource) {
		this.repository = repository;
		this.writer = writer;
		this.tenants = tenants;
		this.hashing = hashing;
		this.timeSource = timeSource;
	}

	@Override
	public ClientRegistration create(TenantId tenantId, CreateClientRequest request) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(request, "Create client request must not be null");
		if (request.type() == ClientType.PUBLIC) {
			return new ClientRegistration(this.writer.store(tenantId, request, null), null);
		}

		IssuedClientSecret secret = IssuedClientSecret.generate();
		try {
			String encodedSecret = this.hashing.encode(secret);
			return new ClientRegistration(this.writer.store(tenantId, request, encodedSecret), secret);
		}
		catch (RuntimeException | Error ex) {
			secret.close();
			throw ex;
		}
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<OAuthClient> findById(TenantId tenantId, ClientId clientId) {
		return this.repository.findById(tenantId, clientId).map(StoredOAuthClient::client);
	}

	@Override
	@Transactional(readOnly = true)
	public Optional<OAuthClient> findByIdentifier(ClientIdentifier identifier) {
		return this.repository.findByIdentifier(identifier).map(StoredOAuthClient::client);
	}

	@Override
	@Transactional(readOnly = true)
	public OAuthClient requireActive(TenantId tenantId, ClientId clientId) {
		this.tenants.requireActive(tenantId);
		return requireActive(requireClient(tenantId, clientId));
	}

	@Override
	@Transactional(propagation = Propagation.MANDATORY,
			noRollbackFor = { TenantDisabledException.class, TenantNotFoundException.class,
					ClientDisabledException.class, ClientNotFoundException.class })
	public OAuthClient requireActiveForWrite(TenantId tenantId, ClientId clientId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(clientId, "Client ID must not be null");
		this.tenants.requireActiveForWrite(tenantId);
		OAuthClient client = this.repository.findByIdForShare(tenantId, clientId)
			.map(StoredOAuthClient::client)
			.orElseThrow(() -> new ClientNotFoundException(tenantId, clientId));
		return requireActive(client);
	}

	@Override
	@Transactional
	public OAuthClient activate(TenantId tenantId, ClientId clientId) {
		return changeStatus(tenantId, clientId, OAuthClient::activate);
	}

	@Override
	@Transactional
	public OAuthClient disable(TenantId tenantId, ClientId clientId) {
		return changeStatus(tenantId, clientId, OAuthClient::disable);
	}

	private OAuthClient changeStatus(TenantId tenantId, ClientId clientId,
			BiFunction<OAuthClient, Instant, OAuthClient> transition) {
		this.tenants.requireActiveForWrite(tenantId);
		OAuthClient current = requireClient(tenantId, clientId);
		OAuthClient changed = transition.apply(current, transitionTime(current));
		return changed == current ? current : updateStatus(current, changed);
	}

	private OAuthClient updateStatus(OAuthClient current, OAuthClient changed) {
		try {
			return this.repository.updateStatus(current, changed);
		}
		catch (ClientConcurrentUpdateException ex) {
			OAuthClient latest = requireClient(current.tenantId(), current.id());
			if (latest.status() == changed.status()) {
				return latest;
			}
			throw ex;
		}
	}

	private Instant transitionTime(OAuthClient current) {
		Instant now = this.timeSource.now();
		return now.isBefore(current.updatedAt()) ? current.updatedAt() : now;
	}

	private OAuthClient requireClient(TenantId tenantId, ClientId clientId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(clientId, "Client ID must not be null");
		return this.repository.findById(tenantId, clientId)
			.map(StoredOAuthClient::client)
			.orElseThrow(() -> new ClientNotFoundException(tenantId, clientId));
	}

	private static OAuthClient requireActive(OAuthClient client) {
		if (!client.isActive()) {
			throw new ClientDisabledException(client.tenantId(), client.id());
		}
		return client;
	}

}
