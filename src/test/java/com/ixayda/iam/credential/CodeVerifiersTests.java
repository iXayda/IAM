package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class CodeVerifiersTests {

	private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

	@Test
	void verifiesTheRfc7636AppendixBVectorAndRejectsOtherProofs() {
		assertThat(CodeVerifiers.matchesS256(VERIFIER, CHALLENGE)).isTrue();
		assertThat(CodeVerifiers.matchesS256("x".repeat(43), CHALLENGE)).isFalse();
		assertThat(CodeVerifiers.matchesS256(null, CHALLENGE)).isFalse();
		assertThat(CodeVerifiers.matchesS256(VERIFIER, null)).isFalse();
		assertThat(CodeVerifiers.matchesS256(VERIFIER, CHALLENGE.substring(0, 42) + "N")).isFalse();
	}

	@ParameterizedTest
	@ValueSource(strings = { "bad space", "bad\nline", "\u2603", "\\", "+", "=" })
	void rejectsMalformedOrNonAsciiProofsEvenWhenTheirHashesMatch(String invalid) throws Exception {
		String verifier = (invalid + "x".repeat(43));
		assertThat(CodeVerifiers.matchesS256(verifier, hash(verifier))).isFalse();
	}

	@ParameterizedTest
	@ValueSource(ints = { 42, 43, 128, 129 })
	void enforcesTheUnreservedVerifierLengthWithoutChangingItsBytes(int length) throws Exception {
		String verifier = "a._~".repeat(33).substring(0, length);
		assertThat(CodeVerifiers.matchesS256(verifier, hash(verifier))).isEqualTo(length >= 43 && length <= 128);
	}

	private static String hash(String value) throws Exception {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
	}

}
