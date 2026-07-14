package com.ixayda.iam.credential.internal.ldap;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;

record LdapExternalCredentialSettings(boolean enabled, ExternalIdentityProviderId providerId,
		Set<TenantId> tenantIds, List<URI> urls, String userSearchBase, String loginAttribute,
		String subjectAttribute, LdapSubjectFormat subjectFormat, LdapTransportSecurity transportSecurity,
		Duration connectTimeout, Duration readTimeout) {

	LdapExternalCredentialSettings {
		Objects.requireNonNull(providerId, "LDAP provider ID must not be null");
		tenantIds = Set.copyOf(Objects.requireNonNull(tenantIds, "LDAP tenant IDs must not be null"));
		urls = List.copyOf(Objects.requireNonNull(urls, "LDAP URLs must not be null"));
		if (enabled && urls.isEmpty()) {
			throw new IllegalArgumentException("LDAP URLs must not be empty");
		}
		Objects.requireNonNull(userSearchBase, "LDAP user search base must not be null");
		Objects.requireNonNull(loginAttribute, "LDAP login attribute must not be null");
		Objects.requireNonNull(subjectAttribute, "LDAP subject attribute must not be null");
		Objects.requireNonNull(subjectFormat, "LDAP subject format must not be null");
		Objects.requireNonNull(transportSecurity, "LDAP transport security must not be null");
		Objects.requireNonNull(connectTimeout, "LDAP connect timeout must not be null");
		Objects.requireNonNull(readTimeout, "LDAP read timeout must not be null");
	}

	boolean supports(TenantId tenantId) {
		return this.enabled
				&& this.tenantIds.contains(Objects.requireNonNull(tenantId, "Tenant ID must not be null"));
	}

}
