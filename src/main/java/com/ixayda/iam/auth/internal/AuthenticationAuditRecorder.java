package com.ixayda.iam.auth.internal;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.ixayda.iam.audit.AppendAuditEvent;
import com.ixayda.iam.audit.AuditAuthenticationFactor;
import com.ixayda.iam.audit.AuditEventOperations;
import com.ixayda.iam.audit.AuditEventOutcome;
import com.ixayda.iam.audit.AuditEventType;
import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaFactor;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.session.SessionAuthenticationFactorType;
import com.ixayda.iam.session.SessionId;
import com.ixayda.iam.session.UserSession;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.springframework.stereotype.Component;

@Component
class AuthenticationAuditRecorder {

	private static final AuditEventType PASSWORD_FAILED = AuditEventType.from("authentication.password.failed");

	private static final AuditEventType MFA_REQUIRED = AuditEventType.from("authentication.mfa.required");

	private static final AuditEventType LOGIN_SUCCEEDED = AuditEventType.from("authentication.login.succeeded");

	private static final AuditEventType LOGIN_THROTTLED = AuditEventType.from("authentication.login.throttled");

	private static final AuditEventType LOGIN_UNAVAILABLE = AuditEventType.from("authentication.login.unavailable");

	private static final AuditEventType MFA_FAILED = AuditEventType.from("authentication.mfa.failed");

	private static final AuditEventType MFA_UNAVAILABLE = AuditEventType.from("authentication.mfa.unavailable");

	private final AuditEventOperations events;

	private final AuthenticationTimeSource timeSource;

	AuthenticationAuditRecorder(AuditEventOperations events, AuthenticationTimeSource timeSource) {
		this.events = events;
		this.timeSource = timeSource;
	}

	void passwordFailed(TenantId tenantId, UserId userId, LoginAttemptSource source) {
		append(tenantId, PASSWORD_FAILED, AuditEventOutcome.FAILED, userId, null,
				AuditAuthenticationFactor.PASSWORD, source, this.timeSource.now(),
				Map.of("reason", "invalid_credentials"));
	}

	void mfaRequired(TenantId tenantId, UserId userId, LoginAttemptSource source, Instant passwordVerifiedAt,
			Set<MfaFactor> factors) {
		String availableFactors = factors.stream()
			.sorted(Comparator.comparing(Enum::name))
			.map((factor) -> factor.name().toLowerCase(Locale.ROOT))
			.collect(Collectors.joining(","));
		append(tenantId, MFA_REQUIRED, AuditEventOutcome.CHALLENGED, userId, null,
				AuditAuthenticationFactor.PASSWORD, source, passwordVerifiedAt,
				Map.of("available_factors", availableFactors));
	}

	void loginSucceeded(UserSession session, LoginAttemptSource source,
			SessionAuthenticationFactorType completedFactor) {
		if (session.authenticationFactors().stream().noneMatch((factor) -> factor.type() == completedFactor)) {
			throw new IllegalArgumentException("Successful login audit factor must exist in the session");
		}
		append(session.tenantId(), LOGIN_SUCCEEDED, AuditEventOutcome.SUCCEEDED, session.userId(), session.id(),
				factor(completedFactor), source, session.authenticatedAt(), Map.of());
	}

	void loginThrottled(TenantId tenantId, LoginAttemptSource source, Duration retryAfter) {
		append(tenantId, LOGIN_THROTTLED, AuditEventOutcome.THROTTLED, null, null,
				AuditAuthenticationFactor.PASSWORD, source, this.timeSource.now(),
				Map.of("retry_after_seconds", Long.toString(Math.max(1, retryAfter.toSeconds()))));
	}

	void loginUnavailable(TenantId tenantId, LoginAttemptSource source, String stage) {
		append(tenantId, LOGIN_UNAVAILABLE, AuditEventOutcome.UNAVAILABLE, null, null,
				AuditAuthenticationFactor.PASSWORD, source, this.timeSource.now(), Map.of("stage", stage));
	}

	void mfaFailed(MfaChallenge challenge, LoginAttemptSource source, MfaFactor factor, String reason) {
		append(challenge.tenantId(), MFA_FAILED, AuditEventOutcome.FAILED, challenge.userId(), null, factor(factor),
				source, this.timeSource.now(), Map.of("reason", reason));
	}

	void mfaUnavailable(MfaChallenge challenge, LoginAttemptSource source, MfaFactor factor, String stage) {
		append(challenge.tenantId(), MFA_UNAVAILABLE, AuditEventOutcome.UNAVAILABLE, challenge.userId(), null,
				factor(factor), source, this.timeSource.now(), Map.of("stage", stage));
	}

	private void append(TenantId tenantId, AuditEventType type, AuditEventOutcome outcome, UserId userId,
			SessionId sessionId, AuditAuthenticationFactor factor, LoginAttemptSource source, Instant occurredAt,
			Map<String, String> attributes) {
		this.events.append(new AppendAuditEvent(tenantId, type, outcome, userId, sessionId, factor, source.value(),
				occurredAt, attributes));
	}

	private static AuditAuthenticationFactor factor(MfaFactor factor) {
		return switch (factor) {
			case TOTP -> AuditAuthenticationFactor.TOTP;
			case RECOVERY_CODE -> AuditAuthenticationFactor.RECOVERY_CODE;
		};
	}

	private static AuditAuthenticationFactor factor(SessionAuthenticationFactorType factor) {
		return switch (factor) {
			case PASSWORD -> AuditAuthenticationFactor.PASSWORD;
			case TOTP -> AuditAuthenticationFactor.TOTP;
			case RECOVERY_CODE -> AuditAuthenticationFactor.RECOVERY_CODE;
		};
	}

}
