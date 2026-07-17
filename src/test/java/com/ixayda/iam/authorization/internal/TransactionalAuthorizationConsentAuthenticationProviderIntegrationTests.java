package com.ixayda.iam.authorization.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.ixayda.iam.ApplicationIntegrationTest;
import com.ixayda.iam.tenant.CreateTenantRequest;
import com.ixayda.iam.tenant.TenantOperations;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

class TransactionalAuthorizationConsentAuthenticationProviderIntegrationTests extends ApplicationIntegrationTest {

	private final List<String> slugsToDelete = new ArrayList<>();

	@Autowired
	private TenantOperations tenants;

	@Autowired
	private JdbcClient jdbcClient;

	@Autowired
	private PlatformTransactionManager transactionManager;

	@AfterEach
	void deleteFixtures() {
		this.slugsToDelete.forEach((slug) -> this.jdbcClient.sql("DELETE FROM tenants WHERE slug = :slug")
			.param("slug", slug)
			.update());
	}

	@Test
	void commitsConsentDenialWorkBeforeRethrowingAccessDenied() {
		String slug = slug();
		OAuth2AuthorizationCodeRequestAuthenticationException denied = failure(OAuth2ErrorCodes.ACCESS_DENIED);
		AuthenticationProvider delegate = providerThatCreatesTenantThenThrows(slug, denied);

		assertThatThrownBy(() -> transactional(delegate).authenticate(mock(Authentication.class))).isSameAs(denied);

		assertThat(this.tenants.findBySlug(slug)).isPresent();
	}

	@Test
	void rollsBackConsentWorkForAllOtherFailures() {
		String slug = slug();
		OAuth2AuthorizationCodeRequestAuthenticationException serverError = failure(OAuth2ErrorCodes.SERVER_ERROR);
		AuthenticationProvider delegate = providerThatCreatesTenantThenThrows(slug, serverError);

		assertThatThrownBy(() -> transactional(delegate).authenticate(mock(Authentication.class))).isSameAs(serverError);

		assertThat(this.tenants.findBySlug(slug)).isEmpty();
	}

	private AuthenticationProvider providerThatCreatesTenantThenThrows(String slug,
			OAuth2AuthorizationCodeRequestAuthenticationException failure) {
		AuthenticationProvider provider = mock(AuthenticationProvider.class);
		when(provider.authenticate(any())).thenAnswer((invocation) -> {
			this.tenants.create(new CreateTenantRequest(slug, "Consent Transaction Test"));
			throw failure;
		});
		return provider;
	}

	private TransactionalAuthorizationConsentAuthenticationProvider transactional(AuthenticationProvider provider) {
		TransactionTemplate transactions = new TransactionTemplate(this.transactionManager);
		transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
		return new TransactionalAuthorizationConsentAuthenticationProvider(provider, transactions);
	}

	private String slug() {
		String slug = "consent-tx-" + UUID.randomUUID().toString().substring(0, 8);
		this.slugsToDelete.add(slug);
		return slug;
	}

	private static OAuth2AuthorizationCodeRequestAuthenticationException failure(String errorCode) {
		return new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(errorCode), null);
	}

}
