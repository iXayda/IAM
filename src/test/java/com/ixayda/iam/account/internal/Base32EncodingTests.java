package com.ixayda.iam.account.internal;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

class Base32EncodingTests {

	@ParameterizedTest
	@MethodSource("rfc4648Vectors")
	void encodesUnpaddedRfc4648Base32(String input, String expected) {
		assertThat(Base32Encoding.encode(input.getBytes(StandardCharsets.US_ASCII))).isEqualTo(expected);
	}

	private static Stream<Arguments> rfc4648Vectors() {
		return Stream.of(Arguments.of("", ""), Arguments.of("f", "MY"), Arguments.of("fo", "MZXQ"),
				Arguments.of("foo", "MZXW6"), Arguments.of("foob", "MZXW6YQ"),
				Arguments.of("fooba", "MZXW6YTB"), Arguments.of("foobar", "MZXW6YTBOI"));
	}

}
