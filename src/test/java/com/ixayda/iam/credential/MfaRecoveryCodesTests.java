package com.ixayda.iam.credential;

import java.util.HashSet;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.*;

class MfaRecoveryCodesTests {

	private final MfaRecoveryCodes codes = new MfaRecoveryCodes();

	@Test
	void generatedCodesHave128BitsOfHexAndAreDistinct() {
		var generated = new HashSet<String>();
		for (int index = 0; index < 1000; index++) {
			String code = this.codes.generate();
			assertThat(code).matches("[0-9a-f]{4}(?:-[0-9a-f]{4}){7}");
			assertThat(generated.add(code)).isTrue();
		}
	}

	@Test
	void digestIsStableAndBoundToItsOwnerFactorAndPurpose() {
		UUID user = UUID.fromString("00000000-0000-0000-0000-000000000001");
		UUID factor = UUID.fromString("00000000-0000-0000-0000-000000000002");
		String code = "0123-4567-89ab-cdef-0123-4567-89ab-cdef";
		String digest = this.codes.digest(user, factor, code);
		// Fixed SHA-256 fixture calculated independently of the Java implementation.
		assertThat(digest).isEqualTo("53396763d3ae21508448f2311464578df666b5bc73e6eb81059e7f504567928d")
				.isEqualTo(this.codes.digest(user, factor, code));
		assertThat(this.codes.digest(factor, user, code)).isNotEqualTo(digest);
		assertThat(this.codes.digest(user, user, code)).isNotEqualTo(digest);
		assertThat(this.codes.digest(user, factor, "0123-4567-89ab-cdef-0123-4567-89ab-cdee")).isNotEqualTo(digest);
		assertThatIllegalArgumentException().isThrownBy(() -> this.codes.digest(null, factor, code));
		assertThatIllegalArgumentException().isThrownBy(() -> this.codes.digest(user, null, code));
	}

	@ParameterizedTest
	@MethodSource("invalidCodes")
	void rejectsAmbiguousMalformedAndOtherCredentialFormats(String code) {
		assertThatIllegalArgumentException().isThrownBy(() -> this.codes.digest(UUID.randomUUID(), UUID.randomUUID(), code))
				.withMessage("Invalid MFA recovery credential");
	}

	static Stream<String> invalidCodes() {
		return Stream.of(null, "", "123456", "0123456789abcdef0123456789abcdef", "0123-4567-89AB-CDEF-0123-4567-89AB-CDEF",
				" 0123-4567-89ab-cdef-0123-4567-89ab-cdef", "0123-4567-89ab-cdef-0123-4567-89ab-cdef\n",
				"０１２３-4567-89ab-cdef-0123-4567-89ab-cdef", "0123-4567-89ab-cdef-0123-4567-89ab-cdeg", "x".repeat(65536));
	}

}
