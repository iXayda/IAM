package com.ixayda.iam.credential.internal.ldap;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;

import javax.naming.InvalidNameException;

import com.ixayda.iam.credential.ExternalCredentialVerificationStatus;
import com.ixayda.iam.credential.ExternalCredentialVerifier;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.ldap.autoconfigure.LdapAutoConfiguration;
import org.springframework.boot.ldap.autoconfigure.LdapConnectionDetails;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

class LdapExternalCredentialConfigurationTests {

	private static final String TENANT_ID = "00000000-0000-0000-0000-000000000002";

	private static final String TEST_PASSWORD = "test-only-directory-secret";

	private static final String[] ENABLED_LDAPS_PROPERTIES = {
			"iam.credential.external.ldap.enabled=true",
			"iam.credential.external.ldap.provider-id=corporate",
			"iam.credential.external.ldap.tenant-ids[0]=" + TENANT_ID,
			"spring.ldap.urls=ldaps://directory.example.test:636",
			"spring.ldap.username=cn=iam-reader,dc=example,dc=test",
			"spring.ldap.password=" + TEST_PASSWORD };

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(LdapAutoConfiguration.class))
		.withBean(MeterRegistry.class, SimpleMeterRegistry::new)
		.withUserConfiguration(LdapExternalCredentialConfiguration.class);

	@Test
	void keepsTheProviderDisabledByDefault() {
		this.contextRunner.run(context -> {
			assertThat(context).hasNotFailed();
			LdapExternalCredentialSettings settings = context.getBean(LdapExternalCredentialSettings.class);

			assertThat(settings.enabled()).isFalse();
			assertThat(settings.providerId())
				.isEqualTo(ExternalIdentityProviderId.from(LdapExternalCredentialProperties.DISABLED_PROVIDER_ID));
			assertThat(settings.tenantIds()).isEmpty();
			assertThat(settings.urls()).isEmpty();
			assertThat(settings.supports(TenantId.DEFAULT)).isFalse();
			assertThat(context.getBean(DirContextAuthenticationStrategy.class))
				.isInstanceOf(SimpleDirContextAuthenticationStrategy.class);
			assertThat(context.getBean(LdapContextSource.class).isPooled()).isFalse();
			ExternalCredentialVerifier verifier = context.getBean(ExternalCredentialVerifier.class);
			try (PasswordAttempt password = new PasswordAttempt(TEST_PASSWORD.toCharArray())) {
				assertThat(verifier.verify(TenantId.DEFAULT, LoginKey.from("alice"), password).status())
					.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
			}
		});
	}

	@Test
	void bindsSecureDefaultsAndAppliesTimeoutsForAnExplicitTenantAllowlist() {
		enabledProvider().run(context -> {
			assertThat(context).hasNotFailed();
			LdapExternalCredentialSettings settings = context.getBean(LdapExternalCredentialSettings.class);
			LdapConnectionDetails connection = context.getBean(LdapConnectionDetails.class);
			LdapProperties properties = context.getBean(LdapProperties.class);
			LdapContextSource contextSource = context.getBean(LdapContextSource.class);

			assertThat(settings.providerId()).isEqualTo(ExternalIdentityProviderId.from("corporate"));
			assertThat(settings.tenantIds()).containsExactly(TenantId.from(TENANT_ID));
			assertThat(settings.urls()).containsExactly(URI.create("ldaps://directory.example.test:636"));
			assertThat(settings.userSearchBase()).isEmpty();
			assertThat(settings.loginAttribute()).isEqualTo("uid");
			assertThat(settings.subjectAttribute()).isEqualTo("entryUUID");
			assertThat(settings.subjectFormat()).isEqualTo(LdapSubjectFormat.TEXT);
			assertThat(settings.transportSecurity()).isEqualTo(LdapTransportSecurity.LDAPS);
			assertThat(settings.connectTimeout()).isEqualTo(Duration.ofSeconds(3));
			assertThat(settings.readTimeout()).isEqualTo(Duration.ofSeconds(5));
			assertThat(settings.supports(TenantId.from(TENANT_ID))).isTrue();
			assertThat(settings.supports(TenantId.DEFAULT)).isFalse();
			assertThat(connection.getUrls()).containsExactly("ldaps://directory.example.test:636");
			assertThat(connection.toString()).isEqualTo("LdapConnectionDetails[redacted]")
				.doesNotContain(TEST_PASSWORD);
			assertThat(properties.getBaseEnvironment())
				.containsEntry("com.sun.jndi.ldap.connect.timeout", "3000")
				.containsEntry("com.sun.jndi.ldap.read.timeout", "5000");
			assertThat(contextSource.isPooled()).isFalse();
			assertThat(context.getBean(DirContextAuthenticationStrategy.class))
				.isInstanceOf(SimpleDirContextAuthenticationStrategy.class);
		});
	}

	@Test
	void configuresStartTlsAndProviderSpecificOverrides() {
		enabledProvider("iam.credential.external.ldap.provider-id=corporate-ad",
				"iam.credential.external.ldap.user-search-base=ou=people",
				"iam.credential.external.ldap.login-attribute=userPrincipalName",
				"iam.credential.external.ldap.subject-attribute=objectGUID",
				"iam.credential.external.ldap.subject-format=binary-base64url",
				"iam.credential.external.ldap.transport-security=START_TLS",
				"iam.credential.external.ldap.connect-timeout=750ms",
				"iam.credential.external.ldap.read-timeout=2s",
				"spring.ldap.urls=ldap://directory.example.test:389")
			.run(context -> {
				assertThat(context).hasNotFailed();
				LdapExternalCredentialSettings settings = context.getBean(LdapExternalCredentialSettings.class);
				LdapProperties properties = context.getBean(LdapProperties.class);

				assertThat(settings.providerId()).isEqualTo(ExternalIdentityProviderId.from("corporate-ad"));
				assertThat(settings.urls()).containsExactly(URI.create("ldap://directory.example.test:389"));
				assertThat(settings.userSearchBase()).isEqualTo("ou=people");
				assertThat(settings.loginAttribute()).isEqualTo("userPrincipalName");
				assertThat(settings.subjectAttribute()).isEqualTo("objectGUID");
				assertThat(settings.subjectFormat()).isEqualTo(LdapSubjectFormat.BINARY_BASE64URL);
				assertThat(settings.transportSecurity()).isEqualTo(LdapTransportSecurity.START_TLS);
				assertThat(settings.connectTimeout()).isEqualTo(Duration.ofMillis(750));
				assertThat(settings.readTimeout()).isEqualTo(Duration.ofSeconds(2));
				assertThat(properties.getBaseEnvironment())
					.containsEntry("java.naming.ldap.attributes.binary", "objectGUID");
				assertThat(context.getBean(DirContextAuthenticationStrategy.class))
					.isInstanceOf(DefaultTlsDirContextAuthenticationStrategy.class);
				assertThat(context.getBean(LdapContextSource.class).isPooled()).isFalse();
			});
	}

	@Test
	void rejectsAnEnabledProviderWithoutAnExplicitProviderId() {
		this.contextRunner.withPropertyValues("iam.credential.external.ldap.enabled=true",
				"iam.credential.external.ldap.tenant-ids[0]=" + TENANT_ID,
				"spring.ldap.urls=ldaps://directory.example.test:636",
				"spring.ldap.username=cn=iam-reader", "spring.ldap.password=" + TEST_PASSWORD)
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	@Test
	void rejectsAnEnabledProviderWithoutTenants() {
		this.contextRunner.withPropertyValues("iam.credential.external.ldap.enabled=true",
				"iam.credential.external.ldap.provider-id=corporate",
				"spring.ldap.urls=ldaps://directory.example.test:636",
				"spring.ldap.username=cn=iam-reader", "spring.ldap.password=" + TEST_PASSWORD)
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class)
				.rootCause()
				.hasMessage("LDAP tenant IDs must not be empty when the provider is enabled"));
	}

	@Test
	void rejectsAnEnabledProviderWithoutAnExplicitServerUrl() {
		this.contextRunner.withPropertyValues("iam.credential.external.ldap.enabled=true",
				"iam.credential.external.ldap.provider-id=corporate",
				"iam.credential.external.ldap.tenant-ids[0]=" + TENANT_ID,
				"spring.ldap.username=cn=iam-reader", "spring.ldap.password=" + TEST_PASSWORD)
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	@Test
	void rejectsMissingSearchCredentials() {
		enabledProvider("spring.ldap.username=")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
		enabledProvider("spring.ldap.password=")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	@Test
	void rejectsAUrlThatDoesNotMatchTheConfiguredTransport() {
		enabledProvider("spring.ldap.urls=ldap://directory.example.test:389")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
		enabledProvider("iam.credential.external.ldap.transport-security=start-tls")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
		enabledProvider("spring.ldap.urls=ldaps://directory.example.test:0")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	@Test
	void rejectsAnInvalidSearchBase() {
		enabledProvider("iam.credential.external.ldap.user-search-base=ou=people,not-a-dn")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(InvalidNameException.class));
	}

	@Test
	void rejectsFilterInjectionThroughAttributeConfiguration() {
		enabledProvider("iam.credential.external.ldap.login-attribute=uid)(|(uid=*")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	@Test
	void rejectsTimeoutsOutsideTheJndiMillisecondRange() {
		enabledProvider("iam.credential.external.ldap.connect-timeout=1ns")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
		enabledProvider("iam.credential.external.ldap.read-timeout=30d")
			.run(context -> assertThat(context.getStartupFailure()).isNotNull()
				.hasRootCauseInstanceOf(IllegalArgumentException.class));
	}

	private ApplicationContextRunner enabledProvider(String... overrides) {
		return this.contextRunner.withPropertyValues(ENABLED_LDAPS_PROPERTIES).withPropertyValues(overrides);
	}

}
