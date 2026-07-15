package com.ixayda.iam.auth.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginIdentifier;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserOperations;
import com.ixayda.iam.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

class TransactionalLocalPasswordLoginTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e62");

	private static final LoginKey LOGIN_KEY = LoginKey.from("alice");

	private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

	private final UserOperations users = mock(UserOperations.class);

	private final PasswordOperations passwords = mock(PasswordOperations.class);

	private final SessionOperations sessions = mock(SessionOperations.class);

	private final LocalPasswordLoginProperties properties =
			new LocalPasswordLoginProperties(Duration.ofHours(8));

	private final TransactionalLocalPasswordLogin login =
			new TransactionalLocalPasswordLogin(this.users, this.passwords, this.sessions, this.properties);

	@Test
	void performsOneDummyVerificationForAnUnknownLogin() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.users.findByLogin(TenantId.DEFAULT, LOGIN_KEY)).thenReturn(Optional.empty());

			LocalPasswordLoginResult result = this.login.authenticate(TenantId.DEFAULT, LOGIN_KEY, attempt);

			assertThat(result).isSameAs(LocalPasswordLoginResult.rejected());
			verify(this.passwords).performDummyVerification(attempt);
			verify(this.passwords, never()).verifyPassword(any(), any(), any());
			verifyNoInteractions(this.sessions);
		}
	}

	@Test
	void performsOneDummyVerificationForAnInactiveLogin() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.users.findByLogin(TenantId.DEFAULT, LOGIN_KEY))
				.thenReturn(Optional.of(user(UserStatus.DISABLED)));

			LocalPasswordLoginResult result = this.login.authenticate(TenantId.DEFAULT, LOGIN_KEY, attempt);

			assertThat(result).isSameAs(LocalPasswordLoginResult.rejected());
			verify(this.passwords).performDummyVerification(attempt);
			verify(this.passwords, never()).verifyPassword(any(), any(), any());
			verifyNoInteractions(this.sessions);
		}
	}

	@Test
	void returnsTheSameGenericRejectionWhenKnownUserVerificationFails() {
		try (PasswordAttempt attempt = attempt()) {
			when(this.users.findByLogin(TenantId.DEFAULT, LOGIN_KEY))
				.thenReturn(Optional.of(user(UserStatus.ACTIVE)));
			when(this.passwords.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).thenReturn(false);

			LocalPasswordLoginResult result = this.login.authenticate(TenantId.DEFAULT, LOGIN_KEY, attempt);

			assertThat(result).isSameAs(LocalPasswordLoginResult.rejected());
			verify(this.passwords, never()).performDummyVerification(any());
			verifyNoInteractions(this.sessions);
		}
	}

	@Test
	void verifiesAndStartsTheSessionWithinOneCall() {
		User user = user(UserStatus.ACTIVE);
		UserSession session = session();
		try (PasswordAttempt attempt = attempt()) {
			when(this.users.findByLogin(TenantId.DEFAULT, LOGIN_KEY)).thenReturn(Optional.of(user));
			when(this.passwords.verifyPassword(TenantId.DEFAULT, USER_ID, attempt)).thenReturn(true);
			when(this.sessions.start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl())).thenReturn(session);

			LocalPasswordLoginResult result = this.login.authenticate(TenantId.DEFAULT, LOGIN_KEY, attempt);

			assertThat(result.session()).contains(session);
			InOrder order = inOrder(this.users, this.passwords, this.sessions);
			order.verify(this.users).findByLogin(TenantId.DEFAULT, LOGIN_KEY);
			order.verify(this.passwords).verifyPassword(TenantId.DEFAULT, USER_ID, attempt);
			order.verify(this.sessions).start(TenantId.DEFAULT, USER_ID, SessionAuthenticationMethod.PASSWORD,
					this.properties.absoluteTtl());
			verify(this.passwords, never()).performDummyVerification(any());
		}
	}

	@Test
	void rejectsNullInputBeforeTouchingAuthenticationState() {
		try (PasswordAttempt attempt = attempt()) {
			assertThatThrownBy(() -> this.login.authenticate(null, LOGIN_KEY, attempt))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.login.authenticate(TenantId.DEFAULT, null, attempt))
				.isInstanceOf(NullPointerException.class);
			assertThatThrownBy(() -> this.login.authenticate(TenantId.DEFAULT, LOGIN_KEY, null))
				.isInstanceOf(NullPointerException.class);
			verifyNoInteractions(this.users, this.passwords, this.sessions);
		}
	}

	private PasswordAttempt attempt() {
		return new PasswordAttempt("candidate-password".toCharArray());
	}

	private User user(UserStatus status) {
		return new User(USER_ID, TenantId.DEFAULT, List.of(LoginIdentifier.username("alice")), status, 0, NOW, NOW,
				null);
	}

	private UserSession session() {
		return UserSession.start(SessionId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e61"), TenantId.DEFAULT, USER_ID,
				SessionAuthenticationMethod.PASSWORD, 0, 0, NOW, NOW.plus(Duration.ofHours(8)));
	}

}
