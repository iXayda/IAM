package com.ixayda.iam.securitystate.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Base64;

import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateToken;
import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;

class SecurityStateKeysTests {

	private static final SecurityStateToken TOKEN =
			SecurityStateToken.from("0123456789abcdefghijklmnopqrstuvwxyz-ABCDEF");

	@Test
	void deterministicallyEncodesAllScopeDimensionsWithoutRawValues() {
		byte[] secret = Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
		SecurityStateKeys keys = new SecurityStateKeys(secret, "iam:security-state");
		Arrays.fill(secret, (byte) 0);
		SecurityStateKey key = new SecurityStateKey(TenantId.DEFAULT, "mfa-login", "user:internal-123");

		String encoded = keys.encode(key, TOKEN);

		assertThat(encoded).startsWith("iam:security-state:")
			.doesNotContain(TenantId.DEFAULT.value().toString(), "mfa-login", "user:internal-123", TOKEN.value());
		assertThat(keys.encode(key, TOKEN)).isEqualTo(encoded);
		assertThat(keys.encode(new SecurityStateKey(TenantId.random(), key.purpose(), key.binding()), TOKEN))
			.isNotEqualTo(encoded);
		assertThat(keys.encode(new SecurityStateKey(key.tenantId(), "password-reset", key.binding()), TOKEN))
			.isNotEqualTo(encoded);
		assertThat(keys.encode(new SecurityStateKey(key.tenantId(), key.purpose(), "user:internal-456"), TOKEN))
			.isNotEqualTo(encoded);
		assertThat(keys.encode(key, SecurityStateToken.from("A".repeat(SecurityStateToken.ENCODED_LENGTH))))
			.isNotEqualTo(encoded);
	}

}
