package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class PasswordCredentialWriterTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e22");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	private static final String NEXT_ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}abcdef0123456789abcdef0123456789";

	private final JdbcPasswordCredentialRepository repository = mock(JdbcPasswordCredentialRepository.class);

	private final UserOperations users = mock(UserOperations.class);

	private final PasswordTimeSource timeSource = mock(PasswordTimeSource.class);

	private final PasswordCredentialWriter writer =
			new PasswordCredentialWriter(this.repository, this.users, this.timeSource);

	@Test
	void insertsTheFirstPasswordUnderAnExclusiveUserGuard() {
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.empty());
		when(this.timeSource.now()).thenReturn(CREATED_AT);

		this.writer.store(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD);

		ArgumentCaptor<PasswordCredential> inserted = ArgumentCaptor.forClass(PasswordCredential.class);
		InOrder order = inOrder(this.users, this.repository, this.timeSource);
		order.verify(this.users).requireActiveForUpdate(TenantId.DEFAULT, USER_ID);
		order.verify(this.repository).findByUserForUpdate(TenantId.DEFAULT, USER_ID);
		order.verify(this.timeSource).now();
		order.verify(this.repository).insert(inserted.capture());
		assertCredential(inserted.getValue(), ENCODED_PASSWORD, 0, CREATED_AT);
	}

	@Test
	void updatesAnExistingPasswordOnce() {
		PasswordCredential current = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));

		this.writer.store(TenantId.DEFAULT, USER_ID, NEXT_ENCODED_PASSWORD);

		ArgumentCaptor<PasswordCredential> changed = ArgumentCaptor.forClass(PasswordCredential.class);
		verify(this.repository).update(org.mockito.ArgumentMatchers.same(current), changed.capture());
		assertCredential(changed.getValue(), NEXT_ENCODED_PASSWORD, 1, CREATED_AT.plusSeconds(1));
		verify(this.repository, never()).insert(any());
	}

	@Test
	void propagatesAWriteConflictWithoutRetrying() {
		PasswordCredential current = credential(ENCODED_PASSWORD, 0, CREATED_AT);
		PasswordCredentialConcurrentUpdateException conflict =
				new PasswordCredentialConcurrentUpdateException(TenantId.DEFAULT, USER_ID, 0);
		when(this.repository.findByUserForUpdate(TenantId.DEFAULT, USER_ID)).thenReturn(Optional.of(current));
		when(this.timeSource.now()).thenReturn(CREATED_AT.plusSeconds(1));
		when(this.repository.update(any(), any())).thenThrow(conflict);

		assertThatThrownBy(() -> this.writer.store(TenantId.DEFAULT, USER_ID, NEXT_ENCODED_PASSWORD))
			.isSameAs(conflict);

		verify(this.repository).findByUserForUpdate(TenantId.DEFAULT, USER_ID);
		verify(this.repository).update(any(), any());
	}

	private static PasswordCredential credential(String encodedPassword, long version, Instant updatedAt) {
		return new PasswordCredential(TenantId.DEFAULT, USER_ID, encodedPassword, version, CREATED_AT, updatedAt);
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
