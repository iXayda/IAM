package com.ixayda.iam.credential.internal.ldap;

import java.util.Arrays;
import java.util.Map;

import com.ixayda.iam.credential.ExternalCredentialVerifier;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ldap.autoconfigure.LdapConnectionDetails;
import org.springframework.boot.ldap.autoconfigure.LdapProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.DirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.SimpleDirContextAuthenticationStrategy;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LdapExternalCredentialProperties.class)
class LdapExternalCredentialConfiguration {

	private static final String CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";

	private static final String READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";

	private static final String BINARY_ATTRIBUTES = "java.naming.ldap.attributes.binary";

	@Bean
	LdapExternalCredentialSettings ldapExternalCredentialSettings(LdapExternalCredentialProperties properties,
			LdapProperties connection) {
		return properties.settings(connection);
	}

	@Bean
	LdapConnectionDetails iamLdapConnectionDetails(LdapProperties properties,
			LdapExternalCredentialSettings settings, Environment environment) {
		properties.getBaseEnvironment().put(CONNECT_TIMEOUT, Long.toString(settings.connectTimeout().toMillis()));
		properties.getBaseEnvironment().put(READ_TIMEOUT, Long.toString(settings.readTimeout().toMillis()));
		configureBinarySubject(properties.getBaseEnvironment(), settings);
		String[] urls = settings.enabled()
				? settings.urls().stream().map(Object::toString).toArray(String[]::new)
				: properties.determineUrls(environment);
		String base = properties.getBase();
		String username = properties.getUsername();
		String password = properties.getPassword();
		return new LdapConnectionDetails() {
			@Override
			public String[] getUrls() {
				return urls.clone();
			}

			@Override
			public String getBase() {
				return base;
			}

			@Override
			public String getUsername() {
				return username;
			}

			@Override
			public String getPassword() {
				return password;
			}

			@Override
			public String toString() {
				return "LdapConnectionDetails[redacted]";
			}
		};
	}

	@Bean
	DirContextAuthenticationStrategy ldapAuthenticationStrategy(LdapExternalCredentialSettings settings) {
		if (!settings.enabled() || settings.transportSecurity() == LdapTransportSecurity.LDAPS) {
			return new SimpleDirContextAuthenticationStrategy();
		}
		DefaultTlsDirContextAuthenticationStrategy strategy = new DefaultTlsDirContextAuthenticationStrategy();
		strategy.setShutdownTlsGracefully(true);
		return strategy;
	}

	@Bean
	ExternalCredentialVerifier ldapExternalCredentialVerifier(ContextSource contextSource,
			LdapExternalCredentialSettings settings, MeterRegistry meterRegistry) {
		LdapClient client = LdapClient.withContextSource(contextSource)
			.ignoreSizeLimitExceededException(false)
			.build();
		return new LdapExternalCredentialVerifier(new SpringLdapUserSearch(client, settings), contextSource, settings,
				meterRegistry);
	}

	private static void configureBinarySubject(Map<String, String> environment,
			LdapExternalCredentialSettings settings) {
		if (!settings.enabled() || settings.subjectFormat() != LdapSubjectFormat.BINARY_BASE64URL) {
			return;
		}
		String subjectAttribute = settings.subjectAttribute();
		String configured = environment.getOrDefault(BINARY_ATTRIBUTES, "").trim();
		boolean alreadyConfigured = Arrays.stream(configured.split("\\s+"))
			.anyMatch(attribute -> attribute.equalsIgnoreCase(subjectAttribute));
		if (!alreadyConfigured) {
			environment.put(BINARY_ATTRIBUTES,
					configured.isEmpty() ? subjectAttribute : configured + " " + subjectAttribute);
		}
	}

}
