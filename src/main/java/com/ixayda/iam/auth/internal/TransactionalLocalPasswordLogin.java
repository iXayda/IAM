package com.ixayda.iam.auth.internal;

import java.util.Objects;
import java.util.Optional;

import com.ixayda.iam.auth.LocalPasswordLoginResult;
import com.ixayda.iam.credential.PasswordAttempt;
import com.ixayda.iam.credential.PasswordOperations;
import com.ixayda.iam.session.SessionAuthenticationMethod;
import com.ixayda.iam.session.SessionOperations;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class TransactionalLocalPasswordLogin {

	private final UserOperations users;

	private final PasswordOperations passwords;

	private final SessionOperations sessions;

	private final LocalPasswordLoginProperties properties;

	TransactionalLocalPasswordLogin(UserOperations users, PasswordOperations passwords, SessionOperations sessions,
			LocalPasswordLoginProperties properties) {
		this.users = users;
		this.passwords = passwords;
		this.sessions = sessions;
		this.properties = properties;
	}

	@Transactional
	public LocalPasswordLoginResult authenticate(TenantId tenantId, LoginKey loginKey, PasswordAttempt password) {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		Objects.requireNonNull(loginKey, "Login key must not be null");
		Objects.requireNonNull(password, "Password attempt must not be null");

		Optional<User> candidate = this.users.findByLogin(tenantId, loginKey);
		User user = candidate.orElse(null);
		if (user == null || !user.isActive()) {
			this.passwords.performDummyVerification(password);
			return LocalPasswordLoginResult.rejected();
		}

		if (!this.passwords.verifyPassword(tenantId, user.id(), password)) {
			return LocalPasswordLoginResult.rejected();
		}

		UserSession session = this.sessions.start(tenantId, user.id(), SessionAuthenticationMethod.PASSWORD,
				this.properties.absoluteTtl());
		return LocalPasswordLoginResult.success(session);
	}

}
