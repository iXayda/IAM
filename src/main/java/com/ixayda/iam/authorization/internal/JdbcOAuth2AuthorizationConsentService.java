package com.ixayda.iam.authorization.internal;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
class JdbcOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	private final JdbcClient jdbcClient;

	JdbcOAuth2AuthorizationConsentService(JdbcClient jdbcClient) {
		this.jdbcClient = Objects.requireNonNull(jdbcClient, "JDBC client must not be null");
	}

	@Override
	@Transactional
	public void save(OAuth2AuthorizationConsent consent) {
		Objects.requireNonNull(consent, "Authorization consent must not be null");
		UUID clientId = parseRequiredUuid(consent.getRegisteredClientId(), "Registered client ID");
		UUID userId = parseRequiredUuid(consent.getPrincipalName(), "Authorization consent principal name");
		Set<String> authorities = authorities(consent.getAuthorities());
		UUID tenantId = activeTenantId(clientId, userId);

		this.jdbcClient.sql("""
				INSERT INTO oauth_authorization_consents
				    (tenant_id, client_id, user_id, principal_name)
				VALUES (:tenantId, :clientId, :userId, :principalName)
				ON CONFLICT (tenant_id, client_id, user_id) DO UPDATE
				SET principal_name = EXCLUDED.principal_name,
				    version = oauth_authorization_consents.version + 1,
				    updated_at = GREATEST(oauth_authorization_consents.updated_at, statement_timestamp())
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("userId", userId)
			.param("principalName", consent.getPrincipalName())
			.update();
		this.jdbcClient.sql("""
				DELETE FROM oauth_authorization_consent_authorities
				WHERE tenant_id = :tenantId AND client_id = :clientId AND user_id = :userId
				""")
			.param("tenantId", tenantId)
			.param("clientId", clientId)
			.param("userId", userId)
			.update();
		for (String authority : authorities) {
			this.jdbcClient.sql("""
					INSERT INTO oauth_authorization_consent_authorities
					    (tenant_id, client_id, user_id, authority)
					VALUES (:tenantId, :clientId, :userId, :authority)
					""")
				.param("tenantId", tenantId)
				.param("clientId", clientId)
				.param("userId", userId)
				.param("authority", authority)
				.update();
		}
	}

	@Override
	@Transactional
	public void remove(OAuth2AuthorizationConsent consent) {
		Objects.requireNonNull(consent, "Authorization consent must not be null");
		UUID clientId = parseRequiredUuid(consent.getRegisteredClientId(), "Registered client ID");
		UUID userId = parseRequiredUuid(consent.getPrincipalName(), "Authorization consent principal name");
		Set<String> expectedAuthorities = authorities(consent.getAuthorities());
		StoredConsent stored = lock(clientId, userId);
		if (stored == null || !loadAuthorities(stored).equals(expectedAuthorities)) {
			return;
		}
		this.jdbcClient.sql("""
				DELETE FROM oauth_authorization_consents
				WHERE tenant_id = :tenantId AND client_id = :clientId AND user_id = :userId
				  AND version = :version
				""")
			.param("tenantId", stored.tenantId())
			.param("clientId", stored.clientId())
			.param("userId", stored.userId())
			.param("version", stored.version())
			.update();
	}

	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		UUID clientId = parseOptionalUuid(registeredClientId);
		UUID userId = parseOptionalUuid(principalName);
		if (clientId == null || userId == null) {
			return null;
		}
		StoredConsent stored = this.jdbcClient.sql("""
				SELECT tenant_id, client_id, user_id, principal_name, version
				FROM oauth_authorization_consents
				WHERE client_id = :clientId AND principal_name = :principalName
				""")
			.param("clientId", clientId)
			.param("principalName", principalName)
			.query((resultSet, rowNumber) -> storedConsent(resultSet))
			.optional()
			.orElse(null);
		return stored == null ? null : toConsent(stored);
	}

	private UUID activeTenantId(UUID clientId, UUID userId) {
		return this.jdbcClient.sql("""
				SELECT clients.tenant_id
				FROM oauth_clients clients
				JOIN tenants ON tenants.tenant_id = clients.tenant_id
				JOIN users ON users.tenant_id = clients.tenant_id AND users.user_id = :userId
				WHERE clients.client_id = :clientId
				  AND clients.status = 'active'
				  AND tenants.status = 'active'
				  AND users.status = 'active'
				FOR SHARE OF clients, tenants, users
				""")
			.param("clientId", clientId)
			.param("userId", userId)
			.query(UUID.class)
			.optional()
			.orElseThrow(() -> new IllegalArgumentException(
					"Authorization consent requires an active client, tenant, and user"));
	}

	private StoredConsent lock(UUID clientId, UUID userId) {
		return this.jdbcClient.sql("""
				SELECT tenant_id, client_id, user_id, principal_name, version
				FROM oauth_authorization_consents
				WHERE client_id = :clientId AND user_id = :userId
				FOR UPDATE
				""")
			.param("clientId", clientId)
			.param("userId", userId)
			.query((resultSet, rowNumber) -> storedConsent(resultSet))
			.optional()
			.orElse(null);
	}

	private OAuth2AuthorizationConsent toConsent(StoredConsent stored) {
		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent
			.withId(stored.clientId().toString(), stored.principalName());
		loadAuthorities(stored).forEach(authority -> builder.authority(new SimpleGrantedAuthority(authority)));
		try {
			return builder.build();
		}
		catch (IllegalArgumentException exception) {
			throw new DataRetrievalFailureException("Stored authorization consent has no authorities", exception);
		}
	}

	private Set<String> loadAuthorities(StoredConsent stored) {
		List<String> values = this.jdbcClient.sql("""
				SELECT authority
				FROM oauth_authorization_consent_authorities
				WHERE tenant_id = :tenantId AND client_id = :clientId AND user_id = :userId
				ORDER BY authority
				""")
			.param("tenantId", stored.tenantId())
			.param("clientId", stored.clientId())
			.param("userId", stored.userId())
			.query(String.class)
			.list();
		return Collections.unmodifiableSet(new LinkedHashSet<>(values));
	}

	private static Set<String> authorities(Set<GrantedAuthority> authorities) {
		if (authorities == null || authorities.isEmpty()) {
			throw new IllegalArgumentException("Authorization consent authorities must not be empty");
		}
		Set<String> values = new LinkedHashSet<>();
		for (GrantedAuthority authority : authorities) {
			String value = authority == null ? null : authority.getAuthority();
			if (value == null || value.isEmpty() || value.length() > 256
					|| !value.chars().allMatch(character -> character >= 33 && character <= 126)) {
				throw new IllegalArgumentException("Authorization consent contains an invalid authority");
			}
			values.add(value);
		}
		return Collections.unmodifiableSet(values);
	}

	private static StoredConsent storedConsent(java.sql.ResultSet resultSet) throws java.sql.SQLException {
		return new StoredConsent(resultSet.getObject("tenant_id", UUID.class),
				resultSet.getObject("client_id", UUID.class), resultSet.getObject("user_id", UUID.class),
				resultSet.getString("principal_name"), resultSet.getLong("version"));
	}

	private static UUID parseRequiredUuid(String value, String name) {
		UUID parsed = parseOptionalUuid(value);
		if (parsed == null) {
			throw new IllegalArgumentException(name + " must be a UUID");
		}
		return parsed;
	}

	private static UUID parseOptionalUuid(String value) {
		try {
			return value == null ? null : UUID.fromString(value);
		}
		catch (IllegalArgumentException exception) {
			return null;
		}
	}

	private record StoredConsent(UUID tenantId, UUID clientId, UUID userId, String principalName, long version) {
	}

}
