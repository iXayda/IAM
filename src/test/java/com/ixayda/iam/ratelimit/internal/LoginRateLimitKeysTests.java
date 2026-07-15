package com.ixayda.iam.ratelimit.internal;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;

import com.ixayda.iam.ratelimit.LoginAttemptKey;
import com.ixayda.iam.ratelimit.LoginAttemptSource;
import com.ixayda.iam.ratelimit.internal.LoginRateLimitKeys.Keys;
import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.LoginKey;
import org.junit.jupiter.api.Test;

class LoginRateLimitKeysTests {

	private static final TenantId TENANT_ID = TenantId.from("00000000-0000-0000-0000-000000000002");

	private final LoginRateLimitKeys encoder = new LoginRateLimitKeys(
			Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), "iam:ratelimit:login");

	@Test
	void producesClusterCompatibleKeysWithoutRawIdentifiers() {
		LoginAttemptKey input = key(TENANT_ID, "alice", "203.0.113.10");

		Keys keys = this.encoder.encode(input);

		assertThat(keys.principal()).startsWith("iam:ratelimit:login:{").contains(":principal:");
		assertThat(keys.source()).startsWith("iam:ratelimit:login:{").contains(":source:");
		assertThat(keys.lease()).startsWith("iam:ratelimit:login:{").contains(":principal-lease:");
		assertThat(hashTag(keys.principal())).isEqualTo(hashTag(keys.source()));
		assertThat(hashTag(keys.principal())).isEqualTo(hashTag(keys.lease()));
		assertThat(keys.principal()).doesNotContain(TENANT_ID.toString(), "alice", "203.0.113.10");
		assertThat(keys.source()).doesNotContain(TENANT_ID.toString(), "alice", "203.0.113.10");
		assertThat(keys.lease()).doesNotContain(TENANT_ID.toString(), "alice", "203.0.113.10");
	}

	@Test
	void scopesPrincipalAndSourceDigestsIndependentlyWithinATenant() {
		Keys original = this.encoder.encode(key(TENANT_ID, "alice", "203.0.113.10"));
		Keys otherSource = this.encoder.encode(key(TENANT_ID, "alice", "203.0.113.11"));
		Keys otherPrincipal = this.encoder.encode(key(TENANT_ID, "bob", "203.0.113.10"));
		Keys otherTenant = this.encoder.encode(key(TenantId.random(), "alice", "203.0.113.10"));

		assertThat(otherSource.principal()).isEqualTo(original.principal());
		assertThat(otherSource.lease()).isEqualTo(original.lease());
		assertThat(otherSource.source()).isNotEqualTo(original.source());
		assertThat(otherPrincipal.principal()).isNotEqualTo(original.principal());
		assertThat(otherPrincipal.lease()).isNotEqualTo(original.lease());
		assertThat(otherPrincipal.source()).isEqualTo(original.source());
		assertThat(otherTenant.principal()).isNotEqualTo(original.principal());
		assertThat(otherTenant.source()).isNotEqualTo(original.source());
		assertThat(otherTenant.lease()).isNotEqualTo(original.lease());
		assertThat(hashTag(otherTenant.principal())).isNotEqualTo(hashTag(original.principal()));
	}

	private static LoginAttemptKey key(TenantId tenantId, String login, String source) {
		return new LoginAttemptKey(tenantId, LoginKey.from(login), LoginAttemptSource.trusted(source));
	}

	private static String hashTag(String key) {
		return key.substring(key.indexOf('{') + 1, key.indexOf('}'));
	}

}
