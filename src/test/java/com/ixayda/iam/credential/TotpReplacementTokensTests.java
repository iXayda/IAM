package com.ixayda.iam.credential;

import java.util.Base64;
import java.util.HashSet;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.*;

class TotpReplacementTokensTests {

	private final TotpReplacementTokens tokens = new TotpReplacementTokens();

	@Test
	void generatesDistinctCanonical256BitSecrets() {
		var generated = new HashSet<String>();
		for (int index = 0; index < 1000; index++) {
			String token = this.tokens.generate();
			byte[] decoded = Base64.getUrlDecoder().decode(token);
			assertThat(decoded).hasSize(32);
			assertThat(token).hasSize(43).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(decoded));
			assertThat(generated.add(token)).isTrue();
			assertThat(this.tokens.digest(UUID.randomUUID(), UUID.randomUUID(), token)).matches("[0-9a-f]{64}");
		}
	}

	@Test
	void digestBindsOwnerReplacementAndPurpose() {
		UUID user = UUID.fromString("00000000-0000-0000-0000-000000000001");
		UUID replacement = UUID.fromString("00000000-0000-0000-0000-000000000002");
		String token = "A".repeat(43);
		// Fixed SHA-256 fixture calculated independently using Python hashlib.
		String digest = this.tokens.digest(user, replacement, token);
		assertThat(digest).isEqualTo("dc1c68ccf341707894eff8ba24f68b3331af6058b8236082742e1fdb531168b0");
		assertThat(digest).isNotEqualTo(new TotpRecoveryTokens().digest(user, replacement, token));
		assertThat(this.tokens.digest(replacement, user, token)).isNotEqualTo(digest);
		assertThat(this.tokens.digest(user, user, token)).isNotEqualTo(digest);
		assertThat(this.tokens.digest(user, replacement, "B" + "A".repeat(42))).isNotEqualTo(digest);
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(null, replacement, token));
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(user, null, token));
	}

	@ParameterizedTest
	@MethodSource("invalidTokens")
	void rejectsMalformedAndNoncanonicalSecretsWithoutEchoingThem(String token) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(UUID.randomUUID(), UUID.randomUUID(), token))
				.withMessage("Invalid TOTP replacement credential");
	}

	static Stream<String> invalidTokens() {
		return Stream.of(null, "", "123456", "A".repeat(42), "A".repeat(44), "A".repeat(42) + "B",
				"A".repeat(43) + "=", "A".repeat(42) + "!", "A".repeat(43) + "\n", "x".repeat(65536));
	}

}
