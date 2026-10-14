package com.ixayda.iam.credential;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import static org.assertj.core.api.Assertions.*;

class PasswordHasherTests {

	private final PasswordHasher hasher = new PasswordHasher(new PasswordPolicy("iam"));

	@Test
	void createsSaltedArgon2idHashesThatTheOfficialEncoderCanVerify() {
		String password = "seven amber lanterns on the hillside";
		String first = this.hasher.hash(password, "alice");
		String second = this.hasher.hash(password, "alice");
		assertThat(first).startsWith("$argon2id$v=19$m=19456,t=2,p=1$").isNotEqualTo(second)
				.doesNotContain(password);
		assertThat(Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8().matches(password, first)).isTrue();
		assertThat(this.hasher.matches(password, first)).isTrue();
		assertThat(this.hasher.matches(password, second)).isTrue();
		assertThat(this.hasher.matches("a different long passphrase", first)).isFalse();
	}

	@Test
	void usesIdenticalUnicodeNormalizationForSettingAndVerification() {
		String hash = this.hasher.hash("Cafe\u0301 lanterns by the riverside", "alice");
		assertThat(this.hasher.matches("Café lanterns by the riverside", hash)).isTrue();
		assertThat(this.hasher.matches("Cafe\u0301 lanterns by the riverside", hash)).isTrue();
	}

	@Test
	void preservesCaseAndLeadingOrTrailingSpaces() {
		String password = " Seven amber lanterns ";
		String hash = this.hasher.hash(password, "alice");
		assertThat(this.hasher.matches(password, hash)).isTrue();
		assertThat(this.hasher.matches(password.strip(), hash)).isFalse();
		assertThat(this.hasher.matches(" seven amber lanterns ", hash)).isFalse();
	}

	@Test
	void preservesUnicodeWhitespaceInNonBlankPasswordHashes() {
		String password = "\u00a0Seven\u202famber lanterns\u00a0";
		String hash = this.hasher.hash(password, "alice");
		assertThat(this.hasher.matches(password, hash)).isTrue();
		assertThat(this.hasher.matches(password.substring(1), hash)).isFalse();
		assertThat(this.hasher.matches(password.replace('\u00a0', ' ').replace('\u202f', ' '), hash))
				.isFalse();
	}

	@Test
	void hashesTheEntireMaximumLengthUnicodePassword() {
		String password = "😀".repeat(256);
		String hash = this.hasher.hash(password, "alice");
		assertThat(this.hasher.matches(password, hash)).isTrue();
		assertThat(this.hasher.matches("😀".repeat(255) + "😁", hash)).isFalse();
	}

	@Test
	void appliesSettingRulesBeforeCreatingAHash() {
		assertThatThrownBy(() -> this.hasher.hash("passwordpassword", "alice"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(PasswordRejectedException.Reason.WEAK_PASSWORD));
		assertThatThrownBy(() -> this.hasher.hash("short", "alice"))
				.isInstanceOf(PasswordRejectedException.class);
		var hasher = new PasswordHasher(new PasswordPolicy("Organization Portal"));
		assertThatThrownBy(() -> hasher.hash("organization portal123!", "alice"))
				.isInstanceOf(PasswordRejectedException.class);
		assertThatThrownBy(() -> hasher.hash("longaccountname15!", "longaccountname15"))
				.isInstanceOf(PasswordRejectedException.class);
	}

	@Test
	void verificationDoesNotApplyTheCurrentPasswordSettingPolicy() {
		var encoder = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
		String hash = encoder.encode("passwordpassword");
		assertThat(this.hasher.matches("passwordpassword", hash)).isTrue();
		var hasher = new PasswordHasher(new PasswordPolicy("Organization Portal"));
		assertThat(hasher.matches("Organization Portal", encoder.encode("Organization Portal"))).isTrue();
	}

	@Test
	void rejectsMalformedInputsAndHashesWithoutThrowingOrPerformingUnboundedWork() {
		String hash = this.hasher.hash("seven amber lanterns on the hillside", "alice");
		for (String password : new String[] { null, "", "\ud800", "x".repeat(65_537), "é".repeat(257) }) {
			assertThat(this.hasher.matches(password, hash)).isFalse();
		}
		for (String malformed : new String[] { null, "", "plain text", "{noop}anything", "$argon2i$v=19$invalid",
				"$argon2id$v=19$m=19456,t=2,p=1$invalid$invalid",
				hash.replace("m=19456", "m=999999"), hash.replace("t=2", "t=99"),
				hash.replace("p=1", "p=0"), hash.replace("p=1", "p=99"), hash.replace("m=19456", "m=1") }) {
			assertThat(this.hasher.matches("seven amber lanterns on the hillside", malformed)).isFalse();
		}
	}

}
