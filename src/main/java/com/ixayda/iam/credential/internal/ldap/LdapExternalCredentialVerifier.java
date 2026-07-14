package com.ixayda.iam.credential.internal.ldap;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import javax.naming.directory.DirContext;

import com.ixayda.iam.credential.ExternalCredentialVerification;
import com.ixayda.iam.credential.ExternalCredentialVerificationStatus;
import com.ixayda.iam.credential.ExternalCredentialVerifier;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.LoginKey;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

final class LdapExternalCredentialVerifier implements ExternalCredentialVerifier {

	static final String VERIFICATION_METRIC = "iam.credential.external.verifications";

	private final LdapUserSearch userSearch;

	private final ContextSource contextSource;

	private final LdapExternalCredentialSettings settings;

	private final Map<ExternalCredentialVerificationStatus, Counter> counters;

	LdapExternalCredentialVerifier(LdapUserSearch userSearch, ContextSource contextSource,
			LdapExternalCredentialSettings settings, MeterRegistry meterRegistry) {
		this.userSearch = Objects.requireNonNull(userSearch, "LDAP user search must not be null");
		this.contextSource = Objects.requireNonNull(contextSource, "LDAP context source must not be null");
		this.settings = Objects.requireNonNull(settings, "LDAP settings must not be null");
		Objects.requireNonNull(meterRegistry, "Meter registry must not be null");
		this.counters = counters(meterRegistry, settings.providerId());
	}

	@Override
	public ExternalIdentityProviderId providerId() {
		return this.settings.providerId();
	}

	@Override
	public ExternalCredentialVerification verify(TenantId tenantId, LoginKey loginKey, PasswordAttempt password) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		Objects.requireNonNull(password, "Password attempt must not be null");
		password.length();

		if (!this.settings.enabled()) {
			return record(ExternalCredentialVerification.unavailable());
		}
		if (!this.settings.supports(tenantId)) {
			return record(ExternalCredentialVerification.rejected());
		}
		requireNoTransaction();

		List<LdapUserCandidate> candidates;
		try {
			candidates = this.userSearch.find(loginKey);
		}
		catch (NamingException | DataAccessException | LdapDirectoryDataException exception) {
			return record(ExternalCredentialVerification.unavailable());
		}
		if (candidates.isEmpty()) {
			return record(ExternalCredentialVerification.rejected());
		}
		if (candidates.size() != 1) {
			return record(ExternalCredentialVerification.unavailable());
		}
		return record(bind(candidates.getFirst(), password));
	}

	private ExternalCredentialVerification bind(LdapUserCandidate candidate, PasswordAttempt password) {
		char[] copiedPassword = password.copy();
		DirContext userContext = null;
		try {
			userContext = this.contextSource.getContext(candidate.absoluteDn(), new String(copiedPassword));
			return ExternalCredentialVerification.verified(candidate.subjectId());
		}
		catch (AuthenticationException exception) {
			return ExternalCredentialVerification.rejected();
		}
		catch (NamingException exception) {
			return ExternalCredentialVerification.unavailable();
		}
		finally {
			Arrays.fill(copiedPassword, '\0');
			LdapUtils.closeContext(userContext);
		}
	}

	private ExternalCredentialVerification record(ExternalCredentialVerification verification) {
		this.counters.get(verification.status()).increment();
		return verification;
	}

	private static Map<ExternalCredentialVerificationStatus, Counter> counters(MeterRegistry registry,
			ExternalIdentityProviderId providerId) {
		Map<ExternalCredentialVerificationStatus, Counter> counters =
				new EnumMap<>(ExternalCredentialVerificationStatus.class);
		for (ExternalCredentialVerificationStatus status : ExternalCredentialVerificationStatus.values()) {
			counters.put(status, Counter.builder(VERIFICATION_METRIC)
				.description("External credential verification outcomes")
				.tag("provider", providerId.value())
				.tag("status", status.name().toLowerCase(Locale.ROOT))
				.register(registry));
		}
		return Map.copyOf(counters);
	}

	private static void requireNoTransaction() {
		if (TransactionSynchronizationManager.isActualTransactionActive()) {
			throw new IllegalTransactionStateException(
					"External credential verification must not run inside a database transaction");
		}
	}

}
