package com.ixayda.iam.credential;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.OptionalLong;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base32;

import org.springframework.stereotype.Component;

/** RFC 6238 with a fixed, interoperable SHA-1 / six-digit / 30-second profile. */
@Component
public final class TotpCodes {

	public String encodeSecret(byte[] secret) {
		return Base32.toBase32String(secret);
	}

	public OptionalLong match(byte[] secret, String code, Instant now, long lastUsedStep) {
		if (code == null || !code.matches("[0-9]{6}")) {
			return OptionalLong.empty();
		}
		long current = Math.floorDiv(now.getEpochSecond(), 30);
		long matched = -1;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(secret, "HmacSHA1"));
			ByteBuffer counter = ByteBuffer.allocate(Long.BYTES);
			int submitted = Integer.parseInt(code);
			for (long step = Math.max(0, current - 1); step <= current + 1; step++) {
				byte[] hash = mac.doFinal(counter.putLong(0, step).array());
				// RFC 4226: dynamic truncation to an unsigned 31-bit value, then six decimal digits.
				int offset = hash[hash.length - 1] & 0x0f;
				int expected = (ByteBuffer.wrap(hash).getInt(offset) & 0x7fff_ffff) % 1_000_000;
				Arrays.fill(hash, (byte) 0);
				if ((expected ^ submitted) == 0) {
					matched = step;
				}
			}
		}
		catch (GeneralSecurityException ex) {
			throw new IllegalStateException("TOTP calculation is unavailable", ex);
		}
		return matched > lastUsedStep ? OptionalLong.of(matched) : OptionalLong.empty();
	}

}
