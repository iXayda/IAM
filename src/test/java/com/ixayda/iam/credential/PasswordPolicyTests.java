package com.ixayda.iam.credential;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static com.ixayda.iam.credential.PasswordRejectedException.Reason.*;
import static org.assertj.core.api.Assertions.*;

class PasswordPolicyTests {

	private final PasswordPolicy policy = new PasswordPolicy("iam");

	@ParameterizedTest
	@ValueSource(strings = { "alllowercasewords", "a long passphrase with spaces", " mixed case phrase " })
	void acceptsPasswordsWithoutCompositionRulesOrTrimming(String password) {
		assertThat(this.policy.normalizeAndValidate(password, "alice")).isEqualTo(password);
	}

	@Test
	void acceptsTheMinimumAndMaximumLengthsIncludingSupplementaryUnicode() {
		for (String password : new String[] { "é".repeat(15), "é".repeat(64), "é".repeat(256),
				"😀".repeat(15), "😀".repeat(256) }) {
			assertThat(this.policy.normalizeAndValidate(password, "alice")).isEqualTo(password);
		}
	}

	@Test
	void normalizesBeforeCountingUnicodeCodePoints() {
		assertThat(this.policy.normalizeAndValidate("e\u0301".repeat(15), "alice")).isEqualTo("é".repeat(15));
		assertRejected("e\u0301".repeat(14), INVALID_LENGTH);
		assertRejected("😀".repeat(8), INVALID_LENGTH);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "short", "fourteen chars" })
	void rejectsMissingAndShortPasswords(String password) {
		assertRejected(password, INVALID_LENGTH);
	}

	@Test
	void rejectsOversizedPasswordsWithoutTruncatingThem() {
		assertRejected("é".repeat(257), INVALID_LENGTH);
		assertRejected("😀".repeat(257), INVALID_LENGTH);
		assertRejected("x".repeat(65_537), INVALID_LENGTH);
	}

	@ParameterizedTest
	@ValueSource(strings = { "long phrase with \ud800", "long phrase with \udc00", "\ud800x long phrase here" })
	void rejectsMalformedUnicode(String password) {
		assertRejected(password, INVALID_UNICODE);
	}

	@ParameterizedTest
	@ValueSource(strings = { "passwordpassword", "PASSWORDPASSWORD", "123456789012345", "1234567890123456",
			"12345678901234567890",
			"thisisapassword", "correct horse battery staple", "               " })
	void rejectsKnownWeakWholePasswords(String password) {
		assertRejected(password, WEAK_PASSWORD);
	}

	@ParameterizedTest
	@ValueSource(ints = { 0x0009, 0x0020, 0x0085, 0x00a0, 0x1680, 0x2000, 0x2007, 0x2028, 0x2029,
			0x202f, 0x205f, 0x3000 })
	void rejectsUnicodeWhitespaceOnlyPasswordsAndContextNames(int codePoint) {
		String space = Character.toString(codePoint);
		assertRejected(space.repeat(15), WEAK_PASSWORD);
		assertRejected((" " + space + "\t").repeat(5), WEAK_PASSWORD);
		assertThatThrownBy(() -> new PasswordPolicy(space)).isInstanceOf(IllegalArgumentException.class)
				.isNotInstanceOf(PasswordRejectedException.class);
		assertThatThrownBy(() -> this.policy.normalizeAndValidate("seven amber lanterns", space))
				.isInstanceOf(IllegalArgumentException.class).isNotInstanceOf(PasswordRejectedException.class);
	}

	@ParameterizedTest
	@ValueSource(ints = { 0x0085, 0x00a0, 0x2007, 0x202f })
	void preservesUnicodeWhitespaceInNonBlankPasswords(int codePoint) {
		String space = Character.toString(codePoint);
		String password = space + "seven" + space + "amber lanterns" + space;
		assertThat(this.policy.normalizeAndValidate(password, "alice")).isEqualTo(password);
	}

	@Test
	void comparesWholePasswordsRatherThanRejectingEmbeddedWordsOrUsernames() {
		assertThat(this.policy.normalizeAndValidate("a passwordpassword with extra uncommon words", "alice"))
				.isNotBlank();
		assertThat(this.policy.normalizeAndValidate("alice carries seven amber lanterns", "alice")).isNotBlank();
		assertThatThrownBy(() -> this.policy.normalizeAndValidate("LONGACCOUNTNAME15", "longaccountname15"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "1", "123", "123456", "123456789", "!", "123!", "longaccountname15" })
	void rejectsAccountNamesAndTheirCommonDerivatives(String suffix) {
		assertThatThrownBy(() -> this.policy.normalizeAndValidate("LONGACCOUNTNAME15" + suffix, "longaccountname15"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "1", "123", "123456", "123456789", "!", "123!", "organization portal" })
	void rejectsServiceNamesAndTheirCommonDerivatives(String suffix) {
		var policy = new PasswordPolicy("Organization Portal");
		assertThatThrownBy(() -> policy.normalizeAndValidate("organization portal" + suffix, "alice"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
	}

	@ParameterizedTest
	@ValueSource(strings = { "ΟΡΓΑΝΙΣΜΟΣΟΡΓΑΝΙΣΜΟΣ", "οργανισμοσοργανισμος",
			"οργανισμοςοργανισμος", "ΟΡΓΑΝΙΣΜΟΣοργανισμος" })
	void rejectsRepeatedGreekNamesRegardlessOfNameAndPasswordCase(String password) {
		for (String name : new String[] { "ΟΡΓΑΝΙΣΜΟΣ", "οργανισμος" }) {
			assertThatThrownBy(() -> this.policy.normalizeAndValidate(password, name))
					.isInstanceOfSatisfying(PasswordRejectedException.class,
							ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
			var policy = new PasswordPolicy(name);
			assertThatThrownBy(() -> policy.normalizeAndValidate(password, "alice"))
					.isInstanceOfSatisfying(PasswordRejectedException.class,
							ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
			assertThat(policy.normalizeAndValidate("ΟΡΓΑΝΙΣΜΟΣ has seven amber lanterns", name))
					.isEqualTo("ΟΡΓΑΝΙΣΜΟΣ has seven amber lanterns");
		}
	}

	@Test
	void normalizesRepeatedNamesAfterJoiningTheirBoundaries() {
		String name = "\u0301identity-account-e";
		String password = "\u0301identity-account-éidentity-account-e";
		assertThatThrownBy(() -> this.policy.normalizeAndValidate(password, name))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
		var policy = new PasswordPolicy(name);
		assertThatThrownBy(() -> policy.normalizeAndValidate(password, "alice"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(WEAK_PASSWORD));
	}

	@Test
	void normalizesContextNamesAndPreservesUnrelatedPassphrases() {
		var policy = new PasswordPolicy("Cafe\u0301 identity portal");
		assertThatThrownBy(() -> policy.normalizeAndValidate("CAFÉ IDENTITY PORTAL123!", "alice"))
				.isInstanceOf(PasswordRejectedException.class);
		assertThatThrownBy(() -> policy.normalizeAndValidate("CAFÉ ACCOUNT NAME123!", "Cafe\u0301 account name"))
				.isInstanceOf(PasswordRejectedException.class);
		assertThat(policy.normalizeAndValidate("a Café identity portal under seven amber lanterns", "alice"))
				.isNotBlank();
		assertThat(policy.normalizeAndValidate("longaccountname15 with seven amber lanterns", "longaccountname15"))
				.isNotBlank();
		assertThat(this.policy.normalizeAndValidate("iam under seven amber lanterns", "alice")).isNotBlank();
	}

	@Test
	void takesTheServiceNameFromApplicationConfiguration() {
		new ApplicationContextRunner().withPropertyValues("spring.application.name=Organization Portal")
				.withUserConfiguration(PasswordPolicy.class).run(context -> {
					assertThat(context).hasNotFailed();
					assertThatThrownBy(() -> context.getBean(PasswordPolicy.class)
							.normalizeAndValidate("ORGANIZATION PORTAL123!", "alice"))
							.isInstanceOf(PasswordRejectedException.class);
				});
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "   ", "\ud800" })
	void requiresValidContextNames(String name) {
		assertThatThrownBy(() -> new PasswordPolicy(name)).isInstanceOf(IllegalArgumentException.class)
				.isNotInstanceOf(PasswordRejectedException.class);
		assertThatThrownBy(() -> this.policy.normalizeAndValidate("seven amber lanterns", name))
				.isInstanceOf(IllegalArgumentException.class).isNotInstanceOf(PasswordRejectedException.class);
	}

	@Test
	void blocklistComparisonDoesNotDependOnTheProcessLocale() {
		Locale original = Locale.getDefault();
		try {
			Locale.setDefault(Locale.forLanguageTag("tr-TR"));
			assertRejected("THISISAPASSWORD", WEAK_PASSWORD);
		}
		finally {
			Locale.setDefault(original);
		}
	}

	@Test
	void rejectionDoesNotExposeTheSubmittedPassword() {
		String password = "private-short";
		assertThatThrownBy(() -> this.policy.normalizeAndValidate(password, "alice"))
				.hasMessage("INVALID_LENGTH").hasMessageNotContaining(password);
	}

	@Test
	void missingEmptyOrMalformedBlocklistsFailClosed() {
		assertThatThrownBy(() -> PasswordPolicy.readBlocklist(null)).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> PasswordPolicy.readBlocklist(stream("# no entries\n")))
				.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> PasswordPolicy.readBlocklist(stream("too-short\n")))
				.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> PasswordPolicy.readBlocklist(new ByteArrayInputStream(new byte[] { (byte) 0xc3, 0x28 })))
				.isInstanceOf(IllegalStateException.class);
	}

	private void assertRejected(String password, PasswordRejectedException.Reason reason) {
		assertThatThrownBy(() -> this.policy.normalizeAndValidate(password, "alice"))
				.isInstanceOfSatisfying(PasswordRejectedException.class,
						ex -> assertThat(ex.reason()).isEqualTo(reason));
	}

	private static ByteArrayInputStream stream(String value) {
		return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
	}

}
