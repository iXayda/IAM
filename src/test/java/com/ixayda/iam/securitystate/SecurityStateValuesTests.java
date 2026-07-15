package com.ixayda.iam.securitystate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ixayda.iam.tenant.TenantId;
import org.junit.jupiter.api.Test;

class SecurityStateValuesTests {

	private static final String TOKEN_VALUE = "0123456789abcdefghijklmnopqrstuvwxyz-ABCDEF";

	@Test
	void validatesAndRedactsSecurityStateKeys() {
		SecurityStateKey key = new SecurityStateKey(TenantId.DEFAULT, "mfa.login_v1", "user:internal-123");

		assertThat(key.purpose()).isEqualTo("mfa.login_v1");
		assertThat(key.binding()).isEqualTo("user:internal-123");
		assertThat(key.toString()).contains("purpose=mfa.login_v1", "binding=redacted")
			.doesNotContain("user:internal-123");
	}

	@Test
	void rejectsInvalidSecurityStateKeys() {
		assertThatThrownBy(() -> new SecurityStateKey(null, "mfa-login", "user-1"))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, null, "user-1"))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "", "user-1"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "Mfa-login", "user-1"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "mfa/login", "user-1"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "a".repeat(65), "user-1"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "mfa-login", null))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "mfa-login", ""))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "mfa-login", "contains space"))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new SecurityStateKey(TenantId.DEFAULT, "mfa-login", "a".repeat(257)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void validatesAndRedactsTokens() {
		SecurityStateToken token = SecurityStateToken.from(TOKEN_VALUE);

		assertThat(token.value()).isEqualTo(TOKEN_VALUE);
		assertThat(token.toString()).isEqualTo("SecurityStateToken[redacted]")
			.doesNotContain(TOKEN_VALUE);
		assertThatThrownBy(() -> SecurityStateToken.from(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> SecurityStateToken.from("a".repeat(42)))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> SecurityStateToken.from("a".repeat(42) + "="))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void exposesIssuedAndUnavailableResultsWithoutTokenDiagnostics() {
		SecurityStateToken token = SecurityStateToken.from(TOKEN_VALUE);
		SecurityStateIssue issued = SecurityStateIssue.issued(token);
		SecurityStateIssue unavailable = SecurityStateIssue.unavailable();

		assertThat(issued.status()).isEqualTo(SecurityStateIssueStatus.ISSUED);
		assertThat(issued.issued()).isTrue();
		assertThat(issued.token()).contains(token);
		assertThat(issued.toString()).isEqualTo("SecurityStateIssue[status=ISSUED]")
			.doesNotContain(TOKEN_VALUE);
		assertThat(unavailable.status()).isEqualTo(SecurityStateIssueStatus.UNAVAILABLE);
		assertThat(unavailable.issued()).isFalse();
		assertThat(unavailable.token()).isEmpty();
		assertThat(SecurityStateIssue.unavailable()).isSameAs(unavailable);
		assertThatThrownBy(() -> SecurityStateIssue.issued(null)).isInstanceOf(NullPointerException.class);
	}

}
