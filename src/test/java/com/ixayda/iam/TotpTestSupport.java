package com.ixayda.iam;

import java.time.Clock;
import java.util.Locale;
import java.util.function.LongFunction;
import java.util.function.Supplier;
import java.util.stream.LongStream;

import com.ixayda.iam.model.IdentityTotpEnrollment;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;

/** TOTP generation and step tracking for sequential fixture operations. */
public final class TotpTestSupport {

	private TotpTestSupport() {
	}

	public static IdentityTotpEnrollment distinctEnrollment(Supplier<IdentityTotpEnrollment> prepare) {
		return distinctEnrollment(prepare, Clock.systemUTC());
	}

	static IdentityTotpEnrollment distinctEnrollment(Supplier<IdentityTotpEnrollment> prepare, Clock clock) {
		for (int attempt = 0; attempt < 10; attempt++) {
			var factor = prepare.get();
			long step = Math.floorDiv(clock.instant().getEpochSecond(), 30);
			if (LongStream.rangeClosed(step - 1, step + 2).mapToObj(value -> otp(factor, value)).distinct().count() == 4) {
				return factor;
			}
		}
		throw new AssertionError("Cannot create distinct adjacent TOTP codes for the fixture");
	}

	/** Conservatively bounds the previous proof's consumption after its request has completed. */
	public static long latestMatchingStep(LongFunction<String> otp, long usedStep, long currentStep) {
		String code = otp.apply(usedStep);
		for (long candidate = currentStep + 1; candidate > usedStep; candidate--) {
			if (code.equals(otp.apply(candidate))) { return candidate; }
		}
		return usedStep;
	}

	public static String otp(IdentityTotpEnrollment factor, long step) {
		byte[] counter = new byte[8];
		for (int i = 7; i >= 0; i--) { counter[i] = (byte) step; step >>>= 8; }
		HMac mac = new HMac(new SHA1Digest());
		mac.init(new KeyParameter(Base32.decode(factor.secret())));
		mac.update(counter, 0, counter.length);
		byte[] hash = new byte[mac.getMacSize()];
		mac.doFinal(hash, 0);
		int offset = hash[hash.length - 1] & 15;
		int number = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16)
				| ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255);
		return String.format(Locale.ROOT, "%06d", number % 1_000_000);
	}

}
