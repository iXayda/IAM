package com.ixayda.iam.credential;

import java.util.Base64;
import java.util.HashSet;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.*;

class TotpRecoveryTokensTests {

	private final TotpRecoveryTokens tokens = new TotpRecoveryTokens();

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
	void digestBindsOwnerRecoveryAndPurpose() {
		UUID user = UUID.fromString("00000000-0000-0000-0000-000000000001");
		UUID recovery = UUID.fromString("00000000-0000-0000-0000-000000000002");
		String token = "A".repeat(43);
		// Fixed SHA-256 fixture calculated independently using Python hashlib.
		String digest = this.tokens.digest(user, recovery, token);
		assertThat(digest).isEqualTo("8c9370de3dca93d1f8ffb9aa3bfbafc2320eb4f986bacc9ef14224802b802ed3");
		assertThat(this.tokens.digest(recovery, user, token)).isNotEqualTo(digest);
		assertThat(this.tokens.digest(user, user, token)).isNotEqualTo(digest);
		assertThat(this.tokens.digest(user, recovery, "B" + "A".repeat(42))).isNotEqualTo(digest);
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(null, recovery, token));
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(user, null, token));
	}

	@ParameterizedTest
	@MethodSource("invalidTokens")
	void rejectsMalformedAndNoncanonicalSecretsWithoutEchoingThem(String token) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(UUID.randomUUID(), UUID.randomUUID(), token))
				.withMessage("Invalid TOTP recovery credential");
	}

	static Stream<String> invalidTokens() {
		return Stream.of(null, "", "123456", "A".repeat(42), "A".repeat(44), "A".repeat(42) + "B",
				"A".repeat(43) + "=", "A".repeat(42) + "!", "A".repeat(43) + "\n", "x".repeat(65536));
	}

}
