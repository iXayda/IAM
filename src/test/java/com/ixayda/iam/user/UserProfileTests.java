package com.ixayda.iam.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class UserProfileTests {

	@Test
	void normalizesOptionalProfileValues() {
		UserProfile profile = new UserProfile("  Alice Jensen  ", " ", " Alice ", null);

		assertThat(profile.displayName()).isEqualTo("Alice Jensen");
		assertThat(profile.formattedName()).isNull();
		assertThat(profile.givenName()).isEqualTo("Alice");
		assertThat(profile.familyName()).isNull();
		assertThat(profile.isEmpty()).isFalse();
		assertThat(UserProfile.empty().isEmpty()).isTrue();
	}

	@Test
	void rejectsOversizedAndControlCharacterValues() {
		assertThatThrownBy(() -> new UserProfile("a".repeat(201), null, null, null))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new UserProfile(null, "Alice\nJensen", null, null))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> new UserProfile("\nAlice", null, null, null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void countsUnicodeCodePointsInsteadOfUtf16CodeUnits() {
		String supplementaryCharacter = "\uD83D\uDE00";

		assertThat(new UserProfile(supplementaryCharacter.repeat(200), null, null, null).displayName())
			.hasSize(400);
		assertThatThrownBy(() -> new UserProfile(supplementaryCharacter.repeat(201), null, null, null))
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void keepsProfileValuesOutOfDiagnosticStrings() {
		UserProfile profile = new UserProfile("Alice Jensen", "Alice Q. Jensen", "Alice", "Jensen");

		assertThat(profile.toString()).doesNotContain("Alice", "Jensen");
	}

}
