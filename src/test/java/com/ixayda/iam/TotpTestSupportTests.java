package com.ixayda.iam;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongFunction;

import com.ixayda.iam.credential.TotpCodes;
import com.ixayda.iam.model.IdentityTotpEnrollment;

import org.bouncycastle.util.encoders.Base32;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class TotpTestSupportTests {

	private static final Instant NOW = Instant.parse("2026-10-24T09:11:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final String COLLIDING_SECRET = "FZ5Z7IQ6M3WKTAWW3YZHO346OXGE35CC";
	private static final String DISTINCT_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

	@Test
	void replacesAnEnrollmentWhoseCurrentCodeWouldConsumeTheNextOperationStep() {
		var collision = factor(COLLIDING_SECRET);
		var replacement = factor(DISTINCT_SECRET);
		var codes = new TotpCodes();
		long step = Math.floorDiv(NOW.getEpochSecond(), 30);
		// Fixed synthetic inputs independently calculated with HMAC-SHA1 at steps 59761102 and 59761103.
		assertThat(TotpTestSupport.otp(collision, step)).isEqualTo("446938");
		assertThat(TotpTestSupport.otp(collision, step + 1)).isEqualTo("446938");
		assertThat(codes.match(Base32.decode(collision.secret()), "446938", NOW, step)).hasValue(step + 1);
		assertThat(codes.match(Base32.decode(collision.secret()), "446938", NOW, step + 1)).isEmpty();

		var attempts = new AtomicInteger();
		var selected = TotpTestSupport.distinctEnrollment(() -> attempts.getAndIncrement() == 0 ? collision : replacement, CLOCK);

		assertThat(selected).isSameAs(replacement);
		assertThat(attempts).hasValue(2);
		byte[] secret = Base32.decode(selected.secret());
		assertThat(codes.match(secret, "205675", NOW, step - 1)).hasValue(step);
		assertThat(codes.match(secret, "161506", NOW, step)).hasValue(step + 1);
		assertThat(codes.match(secret, "161506", NOW, step + 1)).isEmpty();
	}

	@Test
	void retainsTheFirstEnrollmentWhenAdjacentCodesAreDistinct() {
		var factor = factor(DISTINCT_SECRET);
		var attempts = new AtomicInteger();

		assertThat(TotpTestSupport.distinctEnrollment(() -> { attempts.incrementAndGet(); return factor; }, CLOCK)).isSameAs(factor);
		assertThat(attempts).hasValue(1);
	}

	@Test
	void failsAfterBoundedAttemptsInsteadOfReturningACollidingEnrollment() {
		var factor = factor(COLLIDING_SECRET);
		var attempts = new AtomicInteger();

		assertThatExceptionOfType(AssertionError.class).isThrownBy(() ->
				TotpTestSupport.distinctEnrollment(() -> { attempts.incrementAndGet(); return factor; }, CLOCK))
				.withMessage("Cannot create distinct adjacent TOTP codes for the fixture");
		assertThat(attempts).hasValue(10);
	}

	@Test
	void tracksTheHighestStepWhenThePreviousCodeIsVerifiedInTheNextWindow() {
		var enrollment = factor(DISTINCT_SECRET);
		LongFunction<String> otp = step -> TotpTestSupport.otp(enrollment, step);
		long generatedStep = 153567;
		var verifiedAt = Instant.ofEpochMilli(generatedStep * 30000 + 30500);
		var codes = new TotpCodes();
		byte[] secret = Base32.decode(enrollment.secret());
		assertThat(otp.apply(generatedStep)).isEqualTo("468457");
		assertThat(otp.apply(generatedStep + 1)).isEqualTo("214300");
		assertThat(otp.apply(generatedStep + 2)).isEqualTo("468457");

		long retainedStep = TotpTestSupport.latestMatchingStep(otp, generatedStep, generatedStep + 1);

		assertThat(retainedStep).isEqualTo(generatedStep + 2);
		assertThat(codes.match(secret, otp.apply(generatedStep), verifiedAt, generatedStep - 1)).hasValue(retainedStep);
		assertThat(codes.match(secret, otp.apply(generatedStep + 1), verifiedAt, retainedStep)).isEmpty();
		long nextStep = retainedStep + 1;
		assertThat(codes.match(secret, otp.apply(nextStep), Instant.ofEpochSecond(nextStep * 30), retainedStep)).hasValue(nextStep);
	}

	@Test
	void retainsReservedStepsAcrossOrdinaryWindowsAndFutureMarkers() {
		var enrollment = factor(DISTINCT_SECRET);
		LongFunction<String> otp = step -> TotpTestSupport.otp(enrollment, step);
		long step = Math.floorDiv(NOW.getEpochSecond(), 30);

		assertThat(TotpTestSupport.latestMatchingStep(otp, step, step)).isEqualTo(step);
		assertThat(TotpTestSupport.latestMatchingStep(otp, step, step + 1)).isEqualTo(step);
		assertThat(TotpTestSupport.latestMatchingStep(otp, step + 1, step)).isEqualTo(step + 1);
	}

	@Test
	void retainsTheHighestMatchingStepWithinTheCompletedAdjacentWindow() {
		LongFunction<String> otp = step -> step == 10 || step == 12 || step == 14 || step == 16 ? "123456" : "654321";

		assertThat(TotpTestSupport.latestMatchingStep(otp, 10, 14)).isEqualTo(14);
		assertThat(TotpTestSupport.latestMatchingStep(otp, 10, 15)).isEqualTo(16);
	}

	private static IdentityTotpEnrollment factor(String secret) {
		return new IdentityTotpEnrollment(UUID.randomUUID(), UUID.randomUUID(), secret,
				"otpauth://totp/test?secret=" + secret, NOW.plusSeconds(300));
	}

}
