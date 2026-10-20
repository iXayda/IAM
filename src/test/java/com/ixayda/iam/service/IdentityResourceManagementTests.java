package com.ixayda.iam.service;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import com.ixayda.iam.model.IdentityAdministratorContext;
import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityTotpVerification;
import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.TotpAuthenticationContext;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IdentityResourceManagementTests {

	private static final long ORIGINAL_EXPIRY = 1_000L;
	private final UUID actor = UUID.randomUUID();
	private final IdentityResources resources = mock(IdentityResources.class);
	private final IdentityUsers users = mock(IdentityUsers.class);
	private final IdentityBrowserSessions sessions = mock(IdentityBrowserSessions.class);
	private final IdentityAdministratorSessions administrators = mock(IdentityAdministratorSessions.class);
	private final IdentityTotps totps = mock(IdentityTotps.class);
	private final TotpAuthenticationLimits limits = mock(TotpAuthenticationLimits.class);
	private final SecurityAudits audits = mock(SecurityAudits.class);
	private final PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
	private final Runnable persistSession = mock(Runnable.class);
	private final IdentityResource resource = mock(IdentityResource.class);
	private final AtomicBoolean deadlineCrossed = new AtomicBoolean();
	private final TotpAuthenticationContext attribution = new TotpAuthenticationContext(
			"internal:resource-test", InetAddress.getLoopbackAddress(), UUID.randomUUID());
	private final IdentityAdministratorContext context = new IdentityAdministratorContext(
			this.actor, "session", 1L, 1L, null, this.attribution);
	private IdentityResourceManagement management;

	@BeforeEach
	void configureCurrentAdministrator() {
		when(this.manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
		when(this.limits.lock(this.actor, this.attribution)).thenReturn(new TotpAuthenticationLimits.Attempt("source", "account", true));
		when(this.users.lockForStateChange(this.actor)).thenReturn(Optional.of(
				new IdentityUser(this.actor, "alice", "Alice", IdentityUser.Status.ACTIVE, Instant.EPOCH)));
		when(this.sessions.lockOwnedSessionExpiry(this.actor, "session")).thenReturn(Optional.of(ORIGINAL_EXPIRY));
		when(this.sessions.isAuthenticationCurrent(this.actor, 1L, 1L)).thenReturn(true);
		when(this.sessions.isWithinSessionDeadline(1L, ORIGINAL_EXPIRY)).thenAnswer(invocation -> !this.deadlineCrossed.get());
		when(this.administrators.authorities(this.actor, 1L, null)).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_IAM_ADMIN")));
		when(this.totps.verifyInTransaction(this.actor, "123456", this.attribution)).thenReturn(Optional.of(
				new IdentityTotpVerification(this.actor, UUID.randomUUID(), 1L, 1L, Instant.EPOCH, UUID.randomUUID())));
		when(this.resources.create(eq("urn:orders"), eq("Orders"), any())).thenReturn(this.resource);
		var operations = new IdentityAdministratorOperations(this.users, this.sessions, this.administrators,
				this.totps, this.limits, this.audits, this.manager);
		this.management = new IdentityResourceManagement(this.resources, operations);
	}

	@Test
	void commitsAChangeWhileTheOriginalIdleDeadlineIsCurrent() {
		var result = this.management.create(this.context, "urn:orders", "Orders", "123456", this.persistSession);
		assertThat(result.status()).isEqualTo(IdentityResourceManagement.Status.COMPLETED);
		assertThat(result.resource()).isSameAs(this.resource);
		verify(this.sessions).isWithinSessionDeadline(1L, ORIGINAL_EXPIRY);
		verify(this.persistSession).run();
		verify(this.manager).commit(any());
		verify(this.manager, never()).rollback(any());
	}

	@ParameterizedTest
	@EnumSource(DeadlineCrossing.class)
	void crossingTheOriginalIdleDeadlineRollsBackTheOperationAndSession(DeadlineCrossing crossing) {
		if (crossing == DeadlineCrossing.RESOURCE_WRITE) {
			when(this.resources.create(eq("urn:orders"), eq("Orders"), any())).thenAnswer(invocation -> {
				this.deadlineCrossed.set(true);
				return this.resource;
			});
		}
		doAnswer(invocation -> {
			if (crossing == DeadlineCrossing.SESSION_PERSISTENCE) { this.deadlineCrossed.set(true); }
			// A save can renew storage; the authorization decision must retain the locked original deadline.
			when(this.sessions.lockOwnedSessionExpiry(this.actor, "session")).thenReturn(Optional.of(2_000L));
			when(this.sessions.isWithinSessionDeadline(1L, 2_000L)).thenReturn(true);
			return null;
		}).when(this.persistSession).run();
		assertThatIllegalStateException().isThrownBy(() -> this.management.create(
				this.context, "urn:orders", "Orders", "123456", this.persistSession))
				.withMessage("Administrator authentication is no longer current");
		verify(this.resources).create(eq("urn:orders"), eq("Orders"), any());
		verify(this.persistSession).run();
		verify(this.sessions).lockOwnedSessionExpiry(this.actor, "session");
		verify(this.sessions).isWithinSessionDeadline(1L, ORIGINAL_EXPIRY);
		verify(this.manager).rollback(any());
		verify(this.manager, never()).commit(any());
	}

	@Test
	void rejectsAnUnavailableOwnedSessionBeforeConsumingTotpOrWriting() {
		when(this.sessions.lockOwnedSessionExpiry(this.actor, "session")).thenReturn(Optional.empty());
		var result = this.management.create(this.context, "urn:orders", "Orders", "123456", this.persistSession);
		assertThat(result.status()).isEqualTo(IdentityResourceManagement.Status.INVALID_SESSION);
		verifyNoInteractions(this.resources, this.totps, this.persistSession);
	}

	private enum DeadlineCrossing { RESOURCE_WRITE, SESSION_PERSISTENCE }
}
