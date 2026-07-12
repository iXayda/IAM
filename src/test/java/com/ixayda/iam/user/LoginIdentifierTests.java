package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class LoginIdentifierTests {

	@Test
	void canonicalizesLoginIdentifiers() {
		LoginIdentifier username = LoginIdentifier.username("  Alice.Admin  ");
		LoginIdentifier email = LoginIdentifier.email("  Alice@Example.COM  ");
		LoginIdentifier phone = LoginIdentifier.phone("  +1 (555) 123-4567  ");

		assertThat(username.value()).isEqualTo("Alice.Admin");
		assertThat(username.canonicalValue()).isEqualTo("alice.admin");
		assertThat(email.value()).isEqualTo("Alice@Example.COM");
		assertThat(email.canonicalValue()).isEqualTo("alice@example.com");
		assertThat(phone.value()).isEqualTo("+1 (555) 123-4567");
		assertThat(phone.canonicalValue()).isEqualTo("15551234567");
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "ab", "alice user", "alice@example.com", "123-456", "123.456", "用户" })
	void rejectsInvalidOrAmbiguousUsernames(String value) {
		assertThatThrownBy(() -> LoginIdentifier.username(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void enforcesUsernameLengthLimits() {
		assertThat(LoginIdentifier.username("a".repeat(80)).value()).hasSize(80);
		assertThatThrownBy(() -> LoginIdentifier.username("a".repeat(81)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "alice", "alice@@example.com", "alice @example.com", "álice@example.com",
			"alice\u0001@example.com", "alice\u007f@example.com" })
	void rejectsInvalidEmails(String value) {
		assertThatThrownBy(() -> LoginIdentifier.email(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "12345", "+0123456", "+1-555-CALL", "+1234567890123456",
			"+1\t5551234567", "+1\n5551234567" })
	void rejectsInvalidPhones(String value) {
		assertThatThrownBy(() -> LoginIdentifier.phone(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsMismatchedCanonicalValues() {
		assertThatThrownBy(() -> new LoginIdentifier(LoginIdentifierType.EMAIL, "alice@example.com", "bob@example.com"))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void keepsLoginValuesOutOfDiagnosticStrings() {
		LoginIdentifier email = LoginIdentifier.email("Alice@Example.COM");

		assertThat(email.toString()).doesNotContain(email.value(), email.canonicalValue());
	}

}
