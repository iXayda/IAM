package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;
import org.junit.jupiter.api.Test;

class PasswordCredentialTests {

	private static final UserId USER_ID = UserId.from("019bc1e7-14d1-7d38-bd23-0877f2cd0e01");

	private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String ENCODED_PASSWORD =
			"{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG";

	private static final String NEXT_ENCODED_PASSWORD =
			"{pbkdf2@SpringSecurity_v5_8}0123456789abcdef0123456789abcdef";

	@Test
	void createsInitialAndReplacementState() {
		PasswordCredential initial =
				PasswordCredential.initial(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD, CREATED_AT);

		assertThat(initial.tenantId()).isEqualTo(TenantId.DEFAULT);
		assertThat(initial.userId()).isEqualTo(USER_ID);
		assertThat(initial.encodedPassword()).isEqualTo(ENCODED_PASSWORD);
		assertThat(initial.version()).isZero();
		assertThat(initial.createdAt()).isEqualTo(CREATED_AT);
		assertThat(initial.updatedAt()).isEqualTo(CREATED_AT);

		PasswordCredential replacement =
				initial.replaceWith(NEXT_ENCODED_PASSWORD, CREATED_AT.minusSeconds(1));

		assertThat(replacement.encodedPassword()).isEqualTo(NEXT_ENCODED_PASSWORD);
		assertThat(replacement.version()).isOne();
		assertThat(replacement.createdAt()).isEqualTo(CREATED_AT);
		assertThat(replacement.updatedAt()).isEqualTo(CREATED_AT);
	}

	@Test
	void validatesStoredState() {
		assertThatThrownBy(() -> PasswordCredential.initial(null, USER_ID, ENCODED_PASSWORD, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> PasswordCredential.initial(TenantId.DEFAULT, null, ENCODED_PASSWORD, CREATED_AT))
			.isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> PasswordCredential.initial(TenantId.DEFAULT, USER_ID, "plain-password", CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> PasswordCredential.initial(TenantId.DEFAULT, USER_ID,
				"{noop}this-is-a-plaintext-password-and-must-not-be-stored", CREATED_AT))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new PasswordCredential(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD, -1,
				CREATED_AT, CREATED_AT)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new PasswordCredential(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD, 0,
				CREATED_AT, CREATED_AT.minusSeconds(1))).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void keepsEncodedValuesOutOfDiagnosticsAndEquality() {
		PasswordCredential first =
				PasswordCredential.initial(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD, CREATED_AT);
		PasswordCredential second =
				PasswordCredential.initial(TenantId.DEFAULT, USER_ID, ENCODED_PASSWORD, CREATED_AT);

		assertThat(first.toString()).doesNotContain(ENCODED_PASSWORD).contains("encodedPassword=redacted");
		assertThat(first).isNotEqualTo(second);
	}

}
