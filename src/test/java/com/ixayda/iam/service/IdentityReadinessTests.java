package com.ixayda.iam.service;

import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityReadinessTests {
	private final IdentitySigningKeys keys = mock(IdentitySigningKeys.class);
	private final IdentityAuthorizations authorizations = mock(IdentityAuthorizations.class);
	private final SecurityAudits audits = mock(SecurityAudits.class);
	private final PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
	private final IdentityReadiness readiness = new IdentityReadiness(this.keys, this.authorizations, this.audits, this.manager);

	@Test
	void identifiesTheFailedCapabilityWithoutEchoingDiagnostics() {
		when(this.audits.isAvailable()).thenReturn(false, true);
		assertCategory("AUDIT");
		doThrow(new IllegalStateException("private pin")).when(this.authorizations).requireConfigured();
		assertCategory("AUTHORIZATION_PIN");
		when(this.keys.lockForIssuance()).thenThrow(new IllegalStateException("private key"), new QueryTimeoutException("private query"));
		assertCategory("SIGNING");
		assertCategory("TIMEOUT");
		when(this.manager.getTransaction(any())).thenThrow(new CannotCreateTransactionException("private database"));
		assertCategory("DATABASE");
	}

	private void assertCategory(String expected) {
		assertThatThrownBy(this.readiness::requireReady).hasMessage(expected);
	}
}
