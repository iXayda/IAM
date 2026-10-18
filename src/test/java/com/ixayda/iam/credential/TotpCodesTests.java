package com.ixayda.iam.credential;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.*;

class TotpCodesTests {

	private static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
	private final TotpCodes codes = new TotpCodes();

	@ParameterizedTest
	@MethodSource("rfc4226Vectors")
	void matchesRfc4226HotpVectorsUsingTheTimeStepAsCounter(long step, String code) {
		assertThat(this.codes.match(RFC_SECRET, code, Instant.ofEpochSecond(step * 30), -1)).hasValue(step);
	}

	static Stream<Arguments> rfc4226Vectors() {
		return Stream.of(Arguments.of(0L, "755224"), Arguments.of(1L, "287082"), Arguments.of(2L, "359152"),
				Arguments.of(3L, "969429"), Arguments.of(4L, "338314"), Arguments.of(5L, "254676"),
				Arguments.of(6L, "287922"), Arguments.of(7L, "162583"), Arguments.of(8L, "399871"), Arguments.of(9L, "520489"));
	}

	@ParameterizedTest
	@MethodSource("rfc6238Vectors")
	void matchesRfc6238Sha1VectorsWithSixDigitTruncation(long seconds, String code) {
		assertThat(this.codes.match(RFC_SECRET, code, Instant.ofEpochSecond(seconds), -1)).hasValue(seconds / 30);
	}

	static Stream<Arguments> rfc6238Vectors() {
		return Stream.of(Arguments.of(59L, "287082"), Arguments.of(1111111109L, "081804"),
				Arguments.of(1111111111L, "050471"), Arguments.of(1234567890L, "005924"),
				Arguments.of(2000000000L, "279037"), Arguments.of(20000000000L, "353130"));
	}

	@ParameterizedTest
	@MethodSource("largeCounterVectors")
	void preservesAllEightCounterBytesBeyondTheSignedAndUnsigned32BitBoundaries(long step, String code) {
		assertThat(this.codes.match(RFC_SECRET, code, Instant.ofEpochSecond(step * 30), -1)).hasValue(step);
	}

	static Stream<Arguments> largeCounterVectors() {
		// Fixed fixtures computed independently with Python's hmac and struct modules.
		return Stream.of(Arguments.of(1L << 31, "197202"), Arguments.of(1L << 32, "999456"), Arguments.of(1L << 40, "445672"));
	}

	@Test
	void consumesTheHighestMatchingStepWhenAdjacentStepsHaveTheSameCode() {
		Instant now = Instant.ofEpochSecond(910737L * 30);
		assertThat(this.codes.match(RFC_SECRET, "911617", now, -1)).hasValue(910738);
		assertThat(this.codes.match(RFC_SECRET, "911617", now, 910738)).isEmpty();
		assertThat(this.codes.match(RFC_SECRET, "911617", now.plusSeconds(30), 910738)).isEmpty();
	}

	@Test
	void rejectsAWellFormedButIncorrectCode() {
		assertThat(this.codes.match(RFC_SECRET, "000000", Instant.ofEpochSecond(59), -1)).isEmpty();
	}

	@Test
	void limitsDriftToOneStepAndRejectsTheConsumedOrEarlierStep() {
		assertThat(this.codes.match(RFC_SECRET, "287082", Instant.ofEpochSecond(89), -1)).hasValue(1);
		assertThat(this.codes.match(RFC_SECRET, "287082", Instant.ofEpochSecond(90), -1)).isEmpty();
		assertThat(this.codes.match(RFC_SECRET, "287082", Instant.ofEpochSecond(29), -1)).hasValue(1);
		assertThat(this.codes.match(RFC_SECRET, "287082", Instant.ofEpochSecond(59), 1)).isEmpty();
		assertThat(this.codes.match(RFC_SECRET, "287082", Instant.ofEpochSecond(59), 2)).isEmpty();
	}

	@Test
	void currentCodeSurvivesTheNextStepBoundaryButCannotBeReplayed() {
		Instant beforeBoundary = Instant.ofEpochSecond(59, 999_999_999);
		Instant afterBoundary = Instant.ofEpochSecond(60);
		assertThat(this.codes.match(RFC_SECRET, "287082", beforeBoundary, -1)).hasValue(1);
		assertThat(this.codes.match(RFC_SECRET, "287082", afterBoundary, -1)).hasValue(1);
		assertThat(this.codes.match(RFC_SECRET, "287082", beforeBoundary, 1)).isEmpty();
		assertThat(this.codes.match(RFC_SECRET, "287082", afterBoundary, 1)).isEmpty();
	}

	@Test
	void encodesTheRfc4648Base32SecretForAuthenticatorProvisioning() {
		assertThat(this.codes.encodeSecret(RFC_SECRET)).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
	}

	@ParameterizedTest
	@MethodSource("invalidCodes")
	void rejectsNonCanonicalCodesWithoutTrimmingOrAcceptingUnicodeDigits(String code) {
		assertThat(this.codes.match(RFC_SECRET, code, Instant.ofEpochSecond(59), -1)).isEmpty();
	}

	static Stream<String> invalidCodes() {
		return Stream.of(null, "", "28708", "0287082", "287082 ", " 287082", "287082\n", "+87082", "２８７０８２", "٢٨٧٠٨٢", "x".repeat(10000));
	}

}
