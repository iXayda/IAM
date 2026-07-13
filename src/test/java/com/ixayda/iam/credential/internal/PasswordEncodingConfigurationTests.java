package com.ixayda.iam.credential.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.ixayda.iam.credential.PasswordAttempt;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

@SpringJUnitConfig({ PasswordEncodingConfiguration.class, PasswordHashing.class })
class PasswordEncodingConfigurationTests {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private PasswordHashing passwordHashing;

	@Test
	void writesVersionedPbkdf2HashesWithoutTruncatingLongPasswords() {
		String sharedPrefix = "x".repeat(100);
		String password = sharedPrefix + "a";
		String encoded = this.passwordEncoder.encode(password);

		assertThat(encoded).startsWith("{" + PasswordEncodingConfiguration.CURRENT_ENCODING_ID + "}");
		assertThat(this.passwordEncoder.matches(password, encoded)).isTrue();
		assertThat(this.passwordEncoder.matches(sharedPrefix + "b", encoded)).isFalse();
		assertThat(this.passwordEncoder.upgradeEncoding(encoded)).isFalse();
	}

	@Test
	void verifiesBcryptHashesAndMarksThemForUpgrade() {
		String password = "legacy-password";
		String encoded = "{bcrypt}" + new BCryptPasswordEncoder(4).encode(password);

		assertThat(this.passwordEncoder.matches(password, encoded)).isTrue();
		assertThat(this.passwordEncoder.matches("wrong-password", encoded)).isFalse();
		assertThat(this.passwordEncoder.upgradeEncoding(encoded)).isTrue();
	}

	@Test
	void registersTheHashingAdapterInTheSpringContext() {
		assertThat(this.passwordHashing).isNotNull();
	}

	@Test
	void rejectsUnsupportedIdsWithoutExposingPasswordData() {
		try (PasswordAttempt attempt = new PasswordAttempt("candidate-password".toCharArray())) {
			assertThat(this.passwordHashing.matches(attempt,
					"{unknown}encoded-password-value-1234567890")).isFalse();
			assertThat(this.passwordHashing.matches(attempt,
					"{noop}plaintext-password-value-1234567890")).isFalse();
		}
	}

	@Test
	void rejectsDamagedCurrentHashesWithoutExposingPasswordData() {
		String stored = "{" + PasswordEncodingConfiguration.CURRENT_ENCODING_ID + "}0000";

		try (PasswordAttempt attempt = new PasswordAttempt("candidate-password".toCharArray())) {
			assertThat(this.passwordHashing.matches(attempt, stored)).isFalse();
		}
	}

}
