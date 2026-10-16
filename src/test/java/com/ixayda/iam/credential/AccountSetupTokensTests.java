package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class AccountSetupTokensTests {

	private final AccountSetupTokens tokens = new AccountSetupTokens();

	@Test
	void generatesCanonicalUrlSafeSecretsContaining32RandomBytes() {
		Set<String> generated = new HashSet<>();
		for (int i = 0; i < 128; i++) {
			String token = this.tokens.generate();
			assertThat(token).matches("[A-Za-z0-9_-]{43}");
			assertThat(Base64.getUrlDecoder().decode(token)).hasSize(32);
			assertThat(this.tokens.digest(token)).matches("[0-9a-f]{64}");
			assertThat(generated.add(token)).isTrue();
		}
	}

	@Test
	void usesDeterministicPurposeSeparatedSha256Digests() throws Exception {
		String token = this.tokens.generate();
		String expected = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
				.digest(("iam:account-setup:v1:" + token).getBytes(StandardCharsets.US_ASCII)));
		String rawDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
				.digest(token.getBytes(StandardCharsets.US_ASCII)));
		assertThat(this.tokens.digest(token)).isEqualTo(expected).isNotEqualTo(rawDigest);
		assertThat(this.tokens.digest(this.tokens.generate())).isNotEqualTo(expected);
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "short", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/", " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", "ＡAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })
	void rejectsInvalidOrNonCanonicalSecretsWithoutEchoingThem(String token) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest(token))
				.withMessage("Invalid account setup credential");
	}

	@Test
	void boundsInputBeforeDigesting() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokens.digest("A".repeat(65_537)));
	}

}
