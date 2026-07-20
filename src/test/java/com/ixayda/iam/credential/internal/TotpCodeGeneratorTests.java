package com.ixayda.iam.credential.internal;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpCodeGeneratorTests {

	private static final byte[] RFC_6238_SHA1_SECRET =
			"12345678901234567890".getBytes(StandardCharsets.US_ASCII);

	private final TotpCodeGenerator generator = new TotpCodeGenerator();

	@Test
	void generatesTheSixDigitRfc6238Sha1Vectors() {
		assertCode(59, "287082");
		assertCode(1_111_111_109, "081804");
		assertCode(1_111_111_111, "050471");
		assertCode(1_234_567_890, "005924");
		assertCode(2_000_000_000, "279037");
		assertCode(20_000_000_000L, "353130");
	}

	@Test
	void preservesLeadingZeroesAndRequiresSixAsciiDigits() {
		long timeStep = this.generator.timeStepAt(Instant.ofEpochSecond(1_234_567_890));

		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, "005924")).isTrue();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, "5924")).isFalse();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, "00592a")).isFalse();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, "００５９２４")).isFalse();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, null)).isFalse();
	}

	@Test
	void bindsCodesToTheirExactTimeStep() {
		long timeStep = this.generator.timeStepAt(Instant.ofEpochSecond(59));

		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, "287082")).isTrue();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep - 1, "287082")).isFalse();
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep + 1, "287082")).isFalse();
	}

	@Test
	void rejectsInvalidSecretsTimesAndTimeSteps() {
		assertThatThrownBy(() -> this.generator.generate(new byte[19], 0))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.generator.generate(RFC_6238_SHA1_SECRET, -1))
			.isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.generator.timeStepAt(Instant.ofEpochSecond(-1)))
			.isInstanceOf(IllegalArgumentException.class);
	}

	private void assertCode(long epochSecond, String expected) {
		long timeStep = this.generator.timeStepAt(Instant.ofEpochSecond(epochSecond));
		assertThat(this.generator.generate(RFC_6238_SHA1_SECRET, timeStep)).isEqualTo(expected);
		assertThat(this.generator.matches(RFC_6238_SHA1_SECRET, timeStep, expected)).isTrue();
	}

}
