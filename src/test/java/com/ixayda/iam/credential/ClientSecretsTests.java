package com.ixayda.iam.credential;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class ClientSecretsTests {

	private final ClientSecrets secrets = new ClientSecrets();

	@Test
	void generatedSecretsHaveIndependentSaltedHashesAndAReadOnlyOfficialVerifier() {
		String secret = this.secrets.generate();
		String first = this.secrets.hash(secret);
		String second = this.secrets.hash(secret);
		var verifier = this.secrets.verifier();
		assertThat(secret).matches("[A-Za-z0-9_-]{43}");
		assertThat(this.secrets.isSupportedHash(first)).isTrue();
		assertThat(first).isNotEqualTo(second);
		assertThat(verifier.matches(secret, first)).isTrue();
		assertThat(verifier.matches(secret, second)).isTrue();
		assertThat(verifier.matches(this.secrets.generate(), first)).isFalse();
		assertThat(verifier.upgradeEncoding(first)).isFalse();
		assertThatThrownBy(() -> verifier.encode(secret)).isInstanceOf(UnsupportedOperationException.class).hasMessageNotContaining(secret);
	}

	@Test
	void invalidAndNoncanonicalSecretsCannotBeHashedOrVerified() {
		String hash = this.secrets.hash(this.secrets.generate());
		for (String input : List.of("", "a".repeat(42), "a".repeat(44), "A".repeat(42) + "B", "a".repeat(42) + "=", "😀".repeat(43))) {
			assertThatIllegalArgumentException().isThrownBy(() -> this.secrets.hash(input));
			assertThat(this.secrets.verifier().matches(input, hash)).isFalse();
		}
		assertThatIllegalArgumentException().isThrownBy(() -> this.secrets.hash(null));
		assertThat(this.secrets.verifier().matches(null, hash)).isFalse();
	}

	@Test
	void malformedAlgorithmsParametersAndNoncanonicalHashEncodingsAreRejectedBeforeArgon2() {
		String secret = this.secrets.generate();
		String hash = this.secrets.hash(secret);
		for (String value : List.of("", "{noop}" + secret, hash.substring("{argon2}".length()), hash.replace("argon2id", "argon2i"),
				hash.replace("v=19", "v=16"), hash.replace("m=19456", "m=2147483647"), hash.replace("m=19456", "m=8"),
				hash.replace("t=2", "t=2147483647"), hash.replace("p=1", "p=2"), hash + "=", hash + "\n",
				"{argon2}$argon2id$v=19$m=19456,t=2,p=1$" + "A".repeat(21) + "B$" + "A".repeat(43),
				"{argon2}$argon2id$v=19$m=19456,t=2,p=1$" + "A".repeat(22) + "$" + "A".repeat(42) + "B")) {
			assertThat(this.secrets.isSupportedHash(value)).isFalse();
			assertThat(this.secrets.verifier().matches(secret, value)).isFalse();
		}
		assertThat(this.secrets.isSupportedHash(null)).isFalse();
		assertThat(this.secrets.verifier().matches(secret, null)).isFalse();
	}

}
