package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ixayda.iam.credential.NewPassword;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotActiveException;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

class DefaultPasswordOperationsTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e21");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	private static final String NEXT_ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}abcdef0123456789abcdef0123456789";

	private static final String LEGACY_ENCODED_PASSWORD =
			"{bcrypt}$2a$04$legacyEncodedPasswordValue1234567890123456789012";

	private final PasswordCredentialWriter writer = mock(PasswordCredentialWriter.class);

	private final JdbcPasswordCredentialRepository repository = mock(JdbcPasswordCredentialRepository.class);

	private final UserOperations users = mock(UserOperations.class);

	private final PasswordHashing hashing = mock(PasswordHashing.class);

	private final PasswordTimeSource timeSource = mock(PasswordTimeSource.class);

	private final DefaultPasswordOperations operations =
			new DefaultPasswordOperations(this.writer, this.repository, this.users, this.hashing, this.timeSource);

	@BeforeEach
	void startTransactionContext() {
		TransactionSynchronizationManager.setActualTransactionActive(true);
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
		when(this.users.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(user(UserStatus.ACTIVE)));
	}

	@AfterEach
	void clearTransactionContext() {
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(false);
		TransactionSynchronizationManager.setActualTransactionActive(false);
	}

	@Test
	void encodesBeforeEnteringThePasswordWriteTransaction() {
		NewPassword password = new NewPassword("correct-password".toCharArray());
		when(this.hashing.encode(password)).thenReturn(ENCODED_PASSWORD);

		this.operations.setPassword(TenantId.DEFAULT, USER_ID, password);

		InOrder order = inOrder(this.hashing, this.writer);
		order.verify(this.hashing).encode(password);
		order.verify(this.writer).store(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD);
	}

	@Test
	void returnsFalseWhenNoPasswordExists() {
		PasswordAttempt attempt = new PasswordAttempt("attempt".toCharArray());
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.empty());

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.users).findById(TenantId.DEFAULT, USER_ID);
		verify(this.users, never()).requireActiveForWrite(any(), any());
		verify(this.hashing).performDummyMatch(attempt);
	}

	@Test
	void performsOneDummyMatchForAnInactiveUser() {
		PasswordAttempt attempt = new PasswordAttempt("attempt".toCharArray());
		when(this.users.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(user(UserStatus.DISABLED)));

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.hashing).performDummyMatch(attempt);
		verifyNoInteractions(this.repository);
	}

	@Test
	void performsOneDummyMatchForAMissingUser() {
		PasswordAttempt attempt = new PasswordAttempt("attempt".toCharArray());
		when(this.users.findById(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.empty());

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.hashing).performDummyMatch(attempt);
		verifyNoInteractions(this.repository);
	}

	@Test
	void exposesDummyVerificationWithoutApplyingPasswordPolicy() {
		PasswordAttempt attempt = new PasswordAttempt("x".toCharArray());

		this.operations.performDummyVerification(attempt);

		verify(this.hashing).performDummyMatch(attempt);
	}

	@Test
	void returnsFalseBeforeLockingWhenThePasswordDoesNotMatch() {
		PasswordAttempt attempt = new PasswordAttempt("wrong-password".toCharArray());
		PasswordCredential current = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.hashing.matches(attempt, ENCODED_PASSWORD)).thenReturn(false);

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.users, never()).requireActiveForWrite(any(), any());
		verify(this.repository, never()).findByUserForUpdate(any(), any());
		verify(this.repository, never()).update(any(), any());
	}

	@Test
	void returnsTrueAfterLockingAnUnchangedCurrentEncoding() {
		PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray());
		PasswordCredential current = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.hashing.matches(attempt, ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(ENCODED_PASSWORD)).thenReturn(false);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isTrue();

		InOrder order = inOrder(this.users, this.repository, this.hashing);
		order.verify(this.users).findById(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).findByUser(TenantId.DEFAULT, USER_ID);
		order.verify(this.hashing).matches(attempt, ENCODED_PASSWORD);
		order.verify(this.hashing).upgradeEncoding(ENCODED_PASSWORD);
		order.verify(this.users).requireActiveForWrite(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).findByUserForUpdate(TenantId.DEFAULT, USER_ID);
		verify(this.repository, never()).update(any(), any());
	}

	@Test
	void returnsFalseWhenTheUserBecomesInactiveBeforeLocking() {
		PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray());
		PasswordCredential current = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.hashing.matches(attempt, ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(ENCODED_PASSWORD)).thenReturn(false);
		when(this.users.requireActiveForWrite(TenantId.DEFAULT, USER_ID))
			.thenThrow(new UserNotActiveException(TenantId.DEFAULT, USER_ID, UserStatus.DISABLED));

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.hashing).matches(attempt, ENCODED_PASSWORD);
		verify(this.hashing, never()).performDummyMatch(any());
		verify(this.repository, never()).findByUserForUpdate(any(), any());
	}

	@Test
	void preparesALegacyUpgradeBeforeAcquiringLocks() {
		PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray());
		PasswordCredential current = credential(LEGACY_ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.hashing.matches(attempt, LEGACY_ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(LEGACY_ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.reencode(attempt)).thenReturn(NEXT_ENCODED_PASSWORD);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isTrue();

		InOrder order = inOrder(this.hashing, this.users, this.repository);
		order.verify(this.hashing).reencode(attempt);
		order.verify(this.users).requireActiveForWrite(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).findByUserForUpdate(TenantId.DEFAULT, USER_ID);
		ArgumentCaptor<PasswordCredential> changed = ArgumentCaptor.forClass(PasswordCredential.class);
		verify(this.repository).update(org.mockito.ArgumentMatchers.same(current), changed.capture());
		assertCredential(changed.getValue(), NEXT_ENCODED_PASSWORD, 1, CREATED_AT.plusSeconds(1));
	}

	@Test
	void rejectsAnOldPasswordAfterAConcurrentPasswordChange() {
		PasswordAttempt attempt = new PasswordAttempt("old-password".toCharArray());
		PasswordCredential candidate = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		PasswordCredential latest = credential(NEXT_ENCODED_PASSWORD, 1, CREATED_AT.plusSeconds(1));
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(candidate));
		when(this.hashing.matches(attempt, ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(ENCODED_PASSWORD)).thenReturn(false);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(latest));
		when(this.hashing.matches(attempt, NEXT_ENCODED_PASSWORD)).thenReturn(false);

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.hashing).matches(attempt, NEXT_ENCODED_PASSWORD);
		verify(this.repository, never()).update(any(), any());
	}

	@Test
	void acceptsTheSamePasswordAfterAConcurrentReencoding() {
		PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray());
		PasswordCredential candidate = credential(LEGACY_ENCODED_PASSWORD, 0, CREATED_AT);
		PasswordCredential latest = credential(NEXT_ENCODED_PASSWORD, 1, CREATED_AT.plusSeconds(1));
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(candidate));
		when(this.hashing.matches(attempt, LEGACY_ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(LEGACY_ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.reencode(attempt)).thenReturn(ENCODED_PASSWORD);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(latest));
		when(this.hashing.matches(attempt, NEXT_ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(NEXT_ENCODED_PASSWORD)).thenReturn(false);

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isTrue();

		verify(this.hashing).matches(attempt, NEXT_ENCODED_PASSWORD);
		verify(this.repository, never()).update(any(), any());
	}

	@Test
	void returnsFalseWhenTheMatchedCredentialDisappearsBeforeLocking() {
		PasswordAttempt attempt = new PasswordAttempt("correct-password".toCharArray());
		PasswordCredential candidate = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUser(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(candidate));
		when(this.hashing.matches(attempt, ENCODED_PASSWORD)).thenReturn(true);
		when(this.hashing.upgradeEncoding(ENCODED_PASSWORD)).thenReturn(false);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.empty());

		assertThat(this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).isFalse();

		verify(this.repository, never()).update(any(), any());
	}

	@Test
	void requiresAnExistingReadWriteTransactionForVerification() {
		PasswordAttempt attempt = new PasswordAttempt("attempt".toCharArray());
		TransactionSynchronizationManager.setActualTransactionActive(false);

		assertThatThrownBy(() -> this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Password verification requires an existing read-write transaction");
		verifyNoInteractions(this.users, this.repository, this.hashing);
	}

	@Test
	void rejectsAReadOnlyTransactionForVerification() {
		PasswordAttempt attempt = new PasswordAttempt("attempt".toCharArray());
		TransactionSynchronizationManager.setCurrentTransactionReadOnly(true);

		assertThatThrownBy(() -> this.operations.verifyPassword(TenantId.DEFAULT, USER_ID, attempt))
			.isInstanceOf(IllegalTransactionStateException.class)
			.hasMessage("Password verification requires an existing read-write transaction");
		verifyNoInteractions(this.users, this.repository, this.hashing);
	}

	private static PasswordCredential credential(String encodedPassword, long version, Instant updatedAt) {
		return new PasswordCredential(TenantId.DEFAULT, USER_ID, encodedPassword, version, CREATED_AT, updatedAt);
	}

	private static User user(UserStatus status) {
		return new User(USER_ID, TenantId.DEFAULT, List.of(LoginIdentifier.username("password-user")), status, 0,
				CREATED_AT, CREATED_AT, null);
	}

	private static void assertCredential(PasswordCredential credential, String encodedPassword, long version,
			Instant updatedAt) {
		assertThat(credential.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(credential.userId()).isEqualTo(USER_ID);
		assertThat(credential.encodedPassword()).isEqualTo(encodedPassword);
		assertThat(credential.version()).isEqualTo(version);
		assertThat(credential.createdAt()).isEqualTo(CREATED_AT);
		assertThat(credential.updatedAt()).isEqualTo(updatedAt);
	}

}
