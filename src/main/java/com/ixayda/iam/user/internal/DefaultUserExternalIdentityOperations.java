package com.ixayda.iam.user.internal;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityLinkConflictException;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserExternalIdentity;
import com.ixayda.iam.user.UserExternalIdentityOperations;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
class DefaultUserExternalIdentityOperations implements UserExternalIdentityOperations {

	private final JdbcUserExternalIdentityRepository repository;

	private final UserOperations users;

	private final UserTimeSource timeSource;

	DefaultUserExternalIdentityOperations(JdbcUserExternalIdentityRepository repository, UserOperations users,
			UserTimeSource timeSource) {
		this.repository = repository;
		this.users = users;
		this.timeSource = timeSource;
	}

	@Override
	@Transactional
	public UserExternalIdentity link(TenantId tenantId, UserId userId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId) {
		requireKey(tenantId, userId, providerId, subjectId);
		User user = this.users.requireActiveForWrite(tenantId, userId);
		if (!user.tenantId().equals(tenantId) || !user.id().equals(userId)) {
			throw new IllegalStateException("External identity user guard returned a different user");
		}

		Optional<UserExternalIdentity> subjectMapping =
				this.repository.findBySubject(tenantId, providerId, subjectId);
		if (subjectMapping.isPresent()) {
			return requireExactMappingOrThrow(subjectMapping.orElseThrow(), tenantId, userId, providerId, subjectId);
		}
		Optional<UserExternalIdentity> userMapping =
				this.repository.findByUserAndProvider(tenantId, userId, providerId);
		if (userMapping.isPresent()) {
			return requireExactMappingOrThrow(userMapping.orElseThrow(), tenantId, userId, providerId, subjectId);
		}

		UserExternalIdentity identity =
				new UserExternalIdentity(tenantId, providerId, subjectId, userId, this.timeSource.now());
		try {
			return this.repository.insert(identity);
		}
		catch (ExternalSubjectAlreadyLinkedException exception) {
			return this.repository.findBySubject(tenantId, providerId, subjectId)
				.map(current -> requireExactMappingOrThrow(current, tenantId, userId, providerId, subjectId))
				.orElseThrow(() -> conflict(tenantId, userId, providerId));
		}
		catch (UserProviderAlreadyLinkedException exception) {
			throw conflict(tenantId, userId, providerId);
		}
	}

	@Override
	public Optional<UserExternalIdentity> findBySubject(TenantId tenantId,
			ExternalIdentityProviderId providerId, ExternalSubjectId subjectId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		Objects.requireNonNull(subjectId, "External subject ID must not be null");
		return this.repository.findBySubject(tenantId, providerId, subjectId);
	}

	@Override
	public Optional<UserExternalIdentity> findByUserAndProvider(TenantId tenantId, UserId userId,
			ExternalIdentityProviderId providerId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		return this.repository.findByUserAndProvider(tenantId, userId, providerId);
	}

	private static UserExternalIdentity requireExactMappingOrThrow(UserExternalIdentity current, TenantId tenantId,
			UserId userId, ExternalIdentityProviderId providerId, ExternalSubjectId subjectId) {
		if (!current.tenantId().equals(tenantId) || !current.providerId().equals(providerId)) {
			throw new IllegalStateException("External identity lookup returned a different mapping");
		}
		if (!current.userId().equals(userId) || !current.subjectId().equals(subjectId)) {
			throw conflict(tenantId, userId, providerId);
		}
		return current;
	}

	private static ExternalIdentityLinkConflictException conflict(TenantId tenantId, UserId userId,
			ExternalIdentityProviderId providerId) {
		return new ExternalIdentityLinkConflictException(tenantId, userId, providerId);
	}

	private static void requireKey(TenantId tenantId, UserId userId, ExternalIdentityProviderId providerId,
			ExternalSubjectId subjectId) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(userId, "User ID must not be null");
		Objects.requireNonNull(providerId, "External identity provider ID must not be null");
		Objects.requireNonNull(subjectId, "External subject ID must not be null");
	}

}
