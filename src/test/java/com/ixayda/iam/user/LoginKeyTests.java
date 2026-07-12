package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class LoginKeyTests {

	@Test
	void derivesTypeIndependentLoginKeys() {
		assertThat(LoginKey.from("  Alice.Admin  ")).isEqualTo(LoginIdentifier.username("Alice.Admin").loginKey());
		assertThat(LoginKey.from("  Alice@Example.COM  "))
			.isEqualTo(LoginIdentifier.email("Alice@Example.COM").loginKey());
		assertThat(LoginKey.from("  +1 (555) 123-4567  "))
			.isEqualTo(LoginIdentifier.phone("+1 (555) 123-4567").loginKey());
		assertThat(LoginKey.from("123-456").canonicalValue()).isEqualTo("123456");
		assertThat(LoginKey.from("12345").canonicalValue()).isEqualTo("12345");
		assertThat(LoginIdentifier.username("15551234567").loginKey())
			.isEqualTo(LoginIdentifier.phone("+1 (555) 123-4567").loginKey());
	}

	@Test
	void rejectsInvalidLoginKeys() {
		assertThatThrownBy(() -> LoginKey.from(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> LoginKey.from("   ")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> LoginKey.from("alice\u0001@example.com"))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void keepsCanonicalValuesOutOfDiagnosticStrings() {
		LoginKey loginKey = LoginKey.from("Alice@Example.COM");

		assertThat(loginKey.toString()).doesNotContain(loginKey.canonicalValue());
	}

}
