package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ExternalIdentityValuesTests {

	@Test
	void validatesProviderIdentifiers() {
		ExternalIdentityProviderId providerId = ExternalIdentityProviderId.from("corporate");

		assertThat(providerId.value()).isEqualTo("corporate");
		assertThat(providerId.toString()).isEqualTo("corporate");
		assertThat(ExternalIdentityProviderId.from("a").value()).isEqualTo("a");
		assertThat(ExternalIdentityProviderId.from("a".repeat(ExternalIdentityProviderId.MAX_LENGTH)).value())
			.hasSize(ExternalIdentityProviderId.MAX_LENGTH);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", "Corporate", "corporate_ldap", "-corporate", "corporate-", "corporate ldap" })
	void rejectsInvalidProviderIdentifiers(String value) {
		assertThatThrownBy(() -> ExternalIdentityProviderId.from(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsProviderIdentifiersThatAreTooLong() {
		assertThatThrownBy(
				() -> ExternalIdentityProviderId.from("a".repeat(ExternalIdentityProviderId.MAX_LENGTH + 1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void treatsExternalSubjectsAsOpaqueAndKeepsThemOutOfDiagnostics() {
		ExternalSubjectId subjectId = ExternalSubjectId.from("8d86b38a-9e5e-4d4d-a08d-9cb9086a5932");

		assertThat(subjectId.value()).isEqualTo("8d86b38a-9e5e-4d4d-a08d-9cb9086a5932");
		assertThat(subjectId.toString()).isEqualTo("ExternalSubjectId[redacted]")
			.doesNotContain(subjectId.value());
		assertThat(ExternalSubjectId.from(subjectId.value())).isEqualTo(subjectId);
	}

	@ParameterizedTest
	@NullSource
	@ValueSource(strings = { "", " ", " subject", "subject ", "subject value", "subject\nvalue", "sübject" })
	void rejectsInvalidExternalSubjects(String value) {
		assertThatThrownBy(() -> ExternalSubjectId.from(value))
			.isInstanceOfAny(NullPointerException.class, IllegalArgumentException.class);
	}

	@Test
	void rejectsControlCharactersInExternalSubjects() {
		String value = "subject" + Character.toString(0) + "value";

		assertThatThrownBy(() -> ExternalSubjectId.from(value)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void rejectsNonBmpExternalSubjects() {
		assertThatThrownBy(() -> ExternalSubjectId.from("subject-😀"))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void rejectsExternalSubjectsThatAreTooLong() {
		assertThatThrownBy(() -> ExternalSubjectId.from("a".repeat(ExternalSubjectId.MAX_LENGTH + 1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

}
