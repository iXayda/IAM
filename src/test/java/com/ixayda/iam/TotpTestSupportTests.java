package com.ixayda.iam;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

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

	private static IdentityTotpEnrollment factor(String secret) {
		return new IdentityTotpEnrollment(UUID.randomUUID(), UUID.randomUUID(), secret,
				"otpauth://totp/test?secret=" + secret, NOW.plusSeconds(300));
	}

}
