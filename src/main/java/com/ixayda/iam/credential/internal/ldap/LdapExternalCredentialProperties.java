package com.ixayda.iam.credential.internal.ldap;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;

@ConfigurationProperties(LdapExternalCredentialProperties.PREFIX)
record LdapExternalCredentialProperties(boolean enabled, String providerId, Set<UUID> tenantIds,
		String userSearchBase, String loginAttribute, String subjectAttribute, LdapSubjectFormat subjectFormat,
		LdapTransportSecurity transportSecurity, Duration connectTimeout, Duration readTimeout) {

	static final String PREFIX = "iam.credential.external.ldap";

	static final String DISABLED_PROVIDER_ID = "disabled-ldap";

	private static final Pattern ATTRIBUTE_DESCRIPTION =
			Pattern.compile("(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\\.[0-9]+)+)");

	LdapExternalCredentialProperties(@DefaultValue("false") boolean enabled,
			@DefaultValue(DISABLED_PROVIDER_ID) String providerId, Set<UUID> tenantIds,
			@DefaultValue("") String userSearchBase, @DefaultValue("uid") String loginAttribute,
			@DefaultValue("entryUUID") String subjectAttribute,
			@DefaultValue("TEXT") LdapSubjectFormat subjectFormat,
			@DefaultValue("LDAPS") LdapTransportSecurity transportSecurity,
			@DefaultValue("3s") Duration connectTimeout, @DefaultValue("5s") Duration readTimeout) {
		this.enabled = enabled;
		this.providerId = requireText(providerId, "LDAP provider ID");
		this.tenantIds = tenantIds == null ? Set.of() : Set.copyOf(tenantIds);
		this.userSearchBase = canonicalSearchBase(userSearchBase);
		this.loginAttribute = requireAttribute(loginAttribute, "LDAP login attribute");
		this.subjectAttribute = requireAttribute(subjectAttribute, "LDAP subject attribute");
		this.subjectFormat = Objects.requireNonNull(subjectFormat, "LDAP subject format must not be null");
		this.transportSecurity =
				Objects.requireNonNull(transportSecurity, "LDAP transport security must not be null");
		this.connectTimeout = requirePositive(connectTimeout, "LDAP connect timeout");
		this.readTimeout = requirePositive(readTimeout, "LDAP read timeout");

		ExternalIdentityProviderId.from(this.providerId);
		if (this.enabled) {
			if (this.providerId.equals(DISABLED_PROVIDER_ID)) {
				throw new IllegalArgumentException(
						"LDAP provider ID must be configured explicitly when the provider is enabled");
			}
			if (this.tenantIds.isEmpty()) {
				throw new IllegalArgumentException("LDAP tenant IDs must not be empty when the provider is enabled");
			}
		}
	}

	LdapExternalCredentialSettings settings(LdapProperties connection) {
		Objects.requireNonNull(connection, "LDAP connection properties must not be null");
		if (!this.enabled) {
			return new LdapExternalCredentialSettings(false, ExternalIdentityProviderId.from(this.providerId), Set.of(),
					List.of(), this.userSearchBase, this.loginAttribute, this.subjectAttribute, this.subjectFormat,
					this.transportSecurity, this.connectTimeout, this.readTimeout);
		}
		List<URI> urls = requireUrls(connection.getUrls(), this.transportSecurity);
		requireText(connection.getUsername(), "spring.ldap.username");
		requireNonEmpty(connection.getPassword(), "spring.ldap.password");
		Set<TenantId> supportedTenants = this.tenantIds.stream()
			.map(TenantId::new)
			.collect(Collectors.toUnmodifiableSet());
		return new LdapExternalCredentialSettings(true, ExternalIdentityProviderId.from(this.providerId),
				supportedTenants, urls, this.userSearchBase, this.loginAttribute, this.subjectAttribute, this.subjectFormat,
				this.transportSecurity, this.connectTimeout, this.readTimeout);
	}

	private static List<URI> requireUrls(String[] values, LdapTransportSecurity transportSecurity) {
		if (values == null || values.length == 0) {
			throw new IllegalArgumentException("spring.ldap.urls must be configured when the provider is enabled");
		}
		return Arrays.stream(values).map(value -> requireUrl(value, transportSecurity)).toList();
	}

	private static URI requireUrl(String value, LdapTransportSecurity transportSecurity) {
		Objects.requireNonNull(value, "LDAP URL must not be null");
		try {
			URI uri = new URI(value);
			String requiredScheme = transportSecurity == LdapTransportSecurity.LDAPS ? "ldaps" : "ldap";
			String path = uri.getRawPath();
			if (!requiredScheme.equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
					|| uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
					|| path != null && !path.isEmpty() && !path.equals("/")
					|| uri.getPort() == 0 || uri.getPort() > 65_535) {
				throw new IllegalArgumentException(
						"LDAP URLs must be server URLs using the configured transport security");
			}
			return uri;
		}
		catch (URISyntaxException exception) {
			throw new IllegalArgumentException("LDAP URL must be a valid URI", exception);
		}
	}

	private static String canonicalSearchBase(String value) {
		Objects.requireNonNull(value, "LDAP user search base must not be null");
		try {
			return new LdapName(value).toString();
		}
		catch (InvalidNameException exception) {
			throw new IllegalArgumentException("LDAP user search base must be a valid distinguished name", exception);
		}
	}

	private static String requireAttribute(String value, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		if (!ATTRIBUTE_DESCRIPTION.matcher(value).matches()) {
			throw new IllegalArgumentException(name + " must be an LDAP attribute name or numeric OID");
		}
		return value;
	}

	private static Duration requirePositive(Duration value, String name) {
		Objects.requireNonNull(value, name + " must not be null");
		long milliseconds;
		try {
			milliseconds = value.toMillis();
		}
		catch (ArithmeticException exception) {
			throw new IllegalArgumentException(name + " is too large", exception);
		}
		if (milliseconds < 1 || milliseconds > Integer.MAX_VALUE) {
			throw new IllegalArgumentException(name + " must be between 1ms and " + Integer.MAX_VALUE + "ms");
		}
		return value;
	}

	private static String requireText(String value, String name) {
		if (value == null || value.isBlank()) {
			throw new IllegalArgumentException(name + " must not be blank");
		}
		return value;
	}

	private static String requireNonEmpty(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException(name + " must not be empty");
		}
		return value;
	}

}
