package com.ixayda.iam.credential.internal.ldap;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import com.ixayda.iam.credential.ExternalCredentialVerification;
import com.ixayda.iam.credential.ExternalCredentialVerificationStatus;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.ldap.autoconfigure.LdapAutoConfiguration;
import org.springframework.boot.ldap.autoconfigure.embedded.EmbeddedLdapAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.core.support.LdapContextSource;

class LdapExternalCredentialVerifierBindIntegrationTests {

	private static final String BASE_DN = "dc=example,dc=test";

	private static final String MANAGER_DN = "cn=directory-manager";

	private static final String MANAGER_PASSWORD = "test-only-manager-password";

	private static final ExternalIdentityProviderId PROVIDER_ID = ExternalIdentityProviderId.from("corporate");

	private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(EmbeddedLdapAutoConfiguration.class, LdapAutoConfiguration.class))
		.withPropertyValues("spring.ldap.base=" + BASE_DN,
				"spring.ldap.embedded.base-dn[0]=" + BASE_DN,
				"spring.ldap.embedded.ldif=classpath:ldap/external-credential-directory.ldif",
				"spring.ldap.embedded.credential.username=" + MANAGER_DN,
				"spring.ldap.embedded.credential.password=" + MANAGER_PASSWORD);

	@Test
	void performsRealPlainLdapManagerSearchAndUserBindOperations() {
		this.contextRunner.run(context -> {
			assertThat(context).hasNotFailed();
			ContextSource contextSource = context.getBean(ContextSource.class);
			int port = context.getEnvironment().getRequiredProperty("local.ldap.port", Integer.class);

			SimpleMeterRegistry meters = new SimpleMeterRegistry();
			LdapExternalCredentialVerifier byUid = verifier(contextSource, settings(port, "uid"), meters);
			ExternalCredentialVerification verified = verify(byUid, "alice", "test-only-alice-password");
			ExternalCredentialVerification verifiedAgain = verify(byUid, "alice", "test-only-alice-password");
			ExternalCredentialVerification wrongPassword = verify(byUid, "alice", "wrong-password");
			ExternalCredentialVerification unknown = verify(byUid, "unknown", "irrelevant-password");

			assertThat(verified.status()).isEqualTo(ExternalCredentialVerificationStatus.VERIFIED);
			assertThat(verifiedAgain.status()).isEqualTo(ExternalCredentialVerificationStatus.VERIFIED);
			assertThat(verifiedAgain.subjectId()).isEqualTo(verified.subjectId());
			assertThat(wrongPassword.status()).isEqualTo(ExternalCredentialVerificationStatus.REJECTED);
			assertThat(unknown.status()).isEqualTo(ExternalCredentialVerificationStatus.REJECTED);

			LdapExternalCredentialVerifier byMail = verifier(contextSource, settings(port, "mail"), meters);
			assertThat(verify(byMail, "shared@example.test", "test-only-alice-password").status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
			ExternalCredentialVerification escapedFilter = verify(byMail, "alice*)(uid=*)@example.test",
					"test-only-filter-password");
			assertThat(escapedFilter.status()).isEqualTo(ExternalCredentialVerificationStatus.VERIFIED);
			assertThat(escapedFilter.subjectId()).isNotEqualTo(verified.subjectId());

			LdapContextSource invalidManager = contextSource(port, "wrong-manager-password");
			LdapExternalCredentialVerifier unavailable = verifier(invalidManager, settings(port, "uid"), meters);
			assertThat(verify(unavailable, "alice", "test-only-alice-password").status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		});
	}

	private static LdapExternalCredentialVerifier verifier(ContextSource contextSource,
			LdapExternalCredentialSettings settings, SimpleMeterRegistry meterRegistry) {
		LdapClient client = LdapClient.withContextSource(contextSource)
			.ignoreSizeLimitExceededException(false)
			.build();
		return new LdapExternalCredentialVerifier(new SpringLdapUserSearch(client, settings), contextSource, settings,
				meterRegistry);
	}

	private static ExternalCredentialVerification verify(LdapExternalCredentialVerifier verifier, String login,
			String password) {
		try (PasswordAttempt attempt = new PasswordAttempt(password.toCharArray())) {
			return verifier.verify(TenantId.DEFAULT, LoginKey.from(login), attempt);
		}
	}

	private static LdapExternalCredentialSettings settings(int port, String loginAttribute) {
		// Secure transport wiring is covered separately; this server exercises LDAP
		// search and bind protocol behavior.
		return new LdapExternalCredentialSettings(true, PROVIDER_ID, Set.of(TenantId.DEFAULT),
				List.of(URI.create("ldap://127.0.0.1:" + port)), "ou=people", loginAttribute, "entryUUID",
				LdapSubjectFormat.TEXT, LdapTransportSecurity.START_TLS, Duration.ofSeconds(3), Duration.ofSeconds(5));
	}

	private static LdapContextSource contextSource(int port, String managerPassword) {
		LdapContextSource contextSource = new LdapContextSource();
		contextSource.setUrl("ldap://127.0.0.1:" + port);
		contextSource.setBase(BASE_DN);
		contextSource.setUserDn(MANAGER_DN);
		contextSource.setPassword(managerPassword);
		contextSource.afterPropertiesSet();
		return contextSource;
	}

}
