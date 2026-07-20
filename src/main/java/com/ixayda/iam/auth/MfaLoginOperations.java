package com.ixayda.iam.auth;

import com.ixayda.iam.credential.RecoveryCodeAttempt;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.ratelimit.LoginAttemptSource;

public interface MfaLoginOperations {

	/**
	 * Consumes the source-bound challenge before verifying TOTP and starting a session.
	 * The caller retains ownership of {@code code} and should close it after this method
	 * returns.
	 */
	MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, TotpCodeAttempt code);

	/**
	 * Consumes the source-bound challenge before verifying and consuming a recovery code
	 * and starting a session. The caller retains ownership of {@code code} and should
	 * close it after this method returns.
	 */
	MfaLoginResult complete(MfaChallenge challenge, LoginAttemptSource source, RecoveryCodeAttempt code);

}
