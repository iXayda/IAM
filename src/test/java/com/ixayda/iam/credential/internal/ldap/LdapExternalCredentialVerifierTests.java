package com.ixayda.iam.credential.internal.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.naming.directory.DirContext;

import com.ixayda.iam.credential.ExternalCredentialVerification;
import com.ixayda.iam.credential.ExternalCredentialVerificationStatus;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.SizeLimitExceededException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class LdapExternalCredentialVerifierTests {

	private static final TenantId TENANT_ID = TenantId.from("00000000-0000-0000-0000-000000000002");

	private static final TenantId OTHER_TENANT_ID = TenantId.from("00000000-0000-0000-0000-000000000003");

	private static final ExternalIdentityProviderId PROVIDER_ID = ExternalIdentityProviderId.from("corporate");

	private static final LoginKey LOGIN_KEY = LoginKey.from("alice");

	private static final String USER_DN = "uid=alice,ou=people,dc=example,dc=test";

	private static final String PASSWORD = "directory-secret";

	private static final ExternalSubjectId SUBJECT_ID =
			ExternalSubjectId.from("8d86b38a-9e5e-4d4d-a08d-9cb9086a5932");

	private final LdapUserSearch userSearch = mock(LdapUserSearch.class);

	private final ContextSource contextSource = mock(ContextSource.class);

	private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

	private final LdapExternalCredentialVerifier verifier = verifier(enabledSettings());

	@Test
	void verifiesAUniqueSubjectWithAUserBindAndPreservesCallerPasswordOwnership() throws Exception {
		DirContext userContext = mock(DirContext.class);
		when(this.userSearch.find(LOGIN_KEY)).thenReturn(List.of(candidate()));
		when(this.contextSource.getContext(USER_DN, PASSWORD)).thenReturn(userContext);

		try (PasswordAttempt password = password()) {
			ExternalCredentialVerification result = this.verifier.verify(TENANT_ID, LOGIN_KEY, password);

			assertThat(result.status()).isEqualTo(ExternalCredentialVerificationStatus.VERIFIED);
			assertThat(result.subjectId()).contains(SUBJECT_ID);
			assertThat(password.isDestroyed()).isFalse();
			char[] callerCopy = password.copy();
			try {
				assertThat(callerCopy).containsExactly(PASSWORD.toCharArray());
			}
			finally {
				Arrays.fill(callerCopy, '\0');
			}
		}

		verify(this.contextSource).getContext(USER_DN, PASSWORD);
		verify(userContext).close();
		assertThat(counter(ExternalCredentialVerificationStatus.VERIFIED)).isEqualTo(1.0);
	}

	@Test
	void rejectsAnUnknownLoginButTreatsAmbiguousResultsAsUnavailable() {
		when(this.userSearch.find(LOGIN_KEY)).thenReturn(List.of()).thenReturn(List.of(candidate(), candidate()));

		try (PasswordAttempt first = password(); PasswordAttempt second = password()) {
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, first).status())
				.isEqualTo(ExternalCredentialVerificationStatus.REJECTED);
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, second).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		}

		verifyNoInteractions(this.contextSource);
		assertThat(counter(ExternalCredentialVerificationStatus.REJECTED)).isEqualTo(1.0);
		assertThat(counter(ExternalCredentialVerificationStatus.UNAVAILABLE)).isEqualTo(1.0);
	}

	@Test
	void avoidsDirectoryAccessForDisabledOrUnsupportedProviders() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		try (PasswordAttempt first = password(); PasswordAttempt second = password()) {
			assertThat(this.verifier.verify(OTHER_TENANT_ID, LOGIN_KEY, first).status())
				.isEqualTo(ExternalCredentialVerificationStatus.REJECTED);
			assertThat(verifier(disabledSettings()).verify(TENANT_ID, LOGIN_KEY, second).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		}
		finally {
			TransactionSynchronizationManager.setActualTransactionActive(false);
		}

		verifyNoInteractions(this.userSearch, this.contextSource);
	}

	@Test
	void reportsManagerSearchFailuresAsUnavailable() {
		when(this.userSearch.find(LOGIN_KEY))
			.thenThrow(new AuthenticationException())
			.thenThrow(new LdapDirectoryDataException())
			.thenThrow(new SizeLimitExceededException(new javax.naming.SizeLimitExceededException()));

		try (PasswordAttempt first = password(); PasswordAttempt second = password();
				PasswordAttempt third = password()) {
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, first).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, second).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, third).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		}

		verifyNoInteractions(this.contextSource);
	}

	@Test
	void distinguishesInvalidUserCredentialsFromBindTransportFailures() {
		when(this.userSearch.find(LOGIN_KEY)).thenReturn(List.of(candidate()));
		when(this.contextSource.getContext(USER_DN, PASSWORD))
			.thenThrow(new AuthenticationException())
			.thenThrow(new CommunicationException(new javax.naming.CommunicationException()));

		try (PasswordAttempt first = password(); PasswordAttempt second = password()) {
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, first).status())
				.isEqualTo(ExternalCredentialVerificationStatus.REJECTED);
			assertThat(this.verifier.verify(TENANT_ID, LOGIN_KEY, second).status())
				.isEqualTo(ExternalCredentialVerificationStatus.UNAVAILABLE);
		}
	}

	@Test
	void refusesToPerformNetworkAuthenticationInsideADatabaseTransaction() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		try (PasswordAttempt password = password()) {
			assertThatThrownBy(() -> this.verifier.verify(TENANT_ID, LOGIN_KEY, password))
				.isInstanceOf(IllegalTransactionStateException.class)
				.hasMessage("External credential verification must not run inside a database transaction");
		}
		finally {
			TransactionSynchronizationManager.setActualTransactionActive(false);
		}

		verifyNoInteractions(this.userSearch, this.contextSource);
	}

	@Test
	void validatesInputsBeforeDirectoryAccess() {
		try (PasswordAttempt valid = password(); PasswordAttempt destroyed = password()) {
			destroyed.destroy();
			assertThatThrownBy(() -> this.verifier.verify(null, LOGIN_KEY, valid))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.verifier.verify(TENANT_ID, null, valid))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.verifier.verify(TENANT_ID, LOGIN_KEY, null))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.verifier.verify(TENANT_ID, LOGIN_KEY, destroyed))
				.isInstanceOf(IllegalStateException.class);
		}
		verifyNoInteractions(this.userSearch, this.contextSource);
	}

	@Test
	void recordsOnlyLowCardinalityProviderAndStatusTags() {
		when(this.userSearch.find(LOGIN_KEY)).thenReturn(List.of());

		try (PasswordAttempt password = password()) {
			this.verifier.verify(TENANT_ID, LOGIN_KEY, password);
		}

		assertThat(this.meterRegistry.getMeters()).allSatisfy(meter -> {
			assertThat(meter.getId().getName()).isEqualTo(LdapExternalCredentialVerifier.VERIFICATION_METRIC);
			assertThat(meter.getId().getTags()).extracting(tag -> tag.getKey())
				.containsExactlyInAnyOrder("provider", "status");
			assertThat(meter.getId().toString())
				.doesNotContain(LOGIN_KEY.canonicalValue(), USER_DN, SUBJECT_ID.value(), PASSWORD);
			assertThat(meter.getId().getType()).isEqualTo(Meter.Type.COUNTER);
		});
		assertThat(candidate().toString()).isEqualTo("LdapUserCandidate[redacted]")
			.doesNotContain(USER_DN, SUBJECT_ID.value());
	}

	private LdapExternalCredentialVerifier verifier(LdapExternalCredentialSettings settings) {
		return new LdapExternalCredentialVerifier(this.userSearch, this.contextSource, settings, this.meterRegistry);
	}

	private double counter(ExternalCredentialVerificationStatus status) {
		return this.meterRegistry.get(LdapExternalCredentialVerifier.VERIFICATION_METRIC)
			.tags("provider", PROVIDER_ID.value(), "status", status.name().toLowerCase(Locale.ROOT))
			.counter()
			.count();
	}

	private static LdapExternalCredentialSettings enabledSettings() {
		return settings(true, PROVIDER_ID, Set.of(TENANT_ID), List.of(URI.create("ldaps://directory.example.test:636")));
	}

	private static LdapExternalCredentialSettings disabledSettings() {
		return settings(false, ExternalIdentityProviderId.from("disabled-ldap"), Set.of(), List.of());
	}

	private static LdapExternalCredentialSettings settings(boolean enabled, ExternalIdentityProviderId providerId,
			Set<TenantId> tenantIds, List<URI> urls) {
		return new LdapExternalCredentialSettings(enabled, providerId, tenantIds, urls, "ou=people", "uid",
				"entryUUID", LdapSubjectFormat.TEXT, LdapTransportSecurity.LDAPS, Duration.ofSeconds(3),
				Duration.ofSeconds(5));
	}

	private static LdapUserCandidate candidate() {
		return new LdapUserCandidate(USER_DN, SUBJECT_ID);
	}

	private static PasswordAttempt password() {
		return new PasswordAttempt(PASSWORD.toCharArray());
	}

}
