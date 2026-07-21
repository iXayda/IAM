package com.ixayda.iam.account.internal;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.ixayda.iam.credential.TotpCredential;
import com.ixayda.iam.credential.TotpEnrollment;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.User;
import com.ixayda.iam.user.UserId;
import com.ixayda.iam.user.UserNotFoundException;
import com.ixayda.iam.user.UserOperations;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
final class AccountTotpProvisioning {

	private final UserOperations users;

	private final AccountMfaProperties properties;

	AccountTotpProvisioning(UserOperations users, AccountMfaProperties properties) {
		this.users = users;
		this.properties = properties;
	}

	AccountTotpEnrollmentResponse response(TenantId tenantId, UserId userId, TotpEnrollment enrollment) {
		User user = this.users.findById(tenantId, userId)
			.filter(candidate -> !candidate.isDeleted())
			.orElseThrow(() -> new UserNotFoundException(tenantId, userId));
		byte[] secret = enrollment.copySecret();
		try {
			String encodedSecret = Base32Encoding.encode(secret);
			String accountName = user.identifiers().getFirst().value();
			String provisioningUri = UriComponentsBuilder.newInstance()
				.scheme("otpauth")
				.host("totp")
				.pathSegment(this.properties.totpIssuer() + ":" + accountName)
				.queryParam("secret", encodedSecret)
				.queryParam("issuer", this.properties.totpIssuer())
				.queryParam("algorithm", TotpCredential.STANDARD_ALGORITHM.name())
				.queryParam("digits", TotpCredential.STANDARD_DIGITS)
				.queryParam("period", TotpCredential.STANDARD_PERIOD_SECONDS)
				.build()
				.encode(StandardCharsets.UTF_8)
				.toUriString();
			return new AccountTotpEnrollmentResponse(enrollment.credentialId().toString(), enrollment.expiresAt(),
					encodedSecret, provisioningUri);
		}
		finally {
			Arrays.fill(secret, (byte) 0);
		}
	}

}
