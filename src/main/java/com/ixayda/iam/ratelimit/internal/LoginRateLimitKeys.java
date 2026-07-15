package com.ixayda.iam.ratelimit.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.ixayda.iam.ratelimit.LoginAttemptKey;

final class LoginRateLimitKeys {

	private static final String HMAC_ALGORITHM = "HmacSHA256";

	private static final byte[] SEPARATOR = { 0 };

	private final byte[] keySecret;

	private final String keyPrefix;

	LoginRateLimitKeys(byte[] keySecret, String keyPrefix) {
		this.keySecret = keySecret.clone();
		this.keyPrefix = keyPrefix;
	}

	Keys encode(LoginAttemptKey key) {
		String tenant = digest("tenant", key.tenantId().value().toString());
		String principal = digest("principal", key.tenantId().value().toString(), key.loginKey().canonicalValue());
		String source = digest("source", key.tenantId().value().toString(), key.source().value());
		String slotPrefix = this.keyPrefix + ":{" + tenant + "}:";
		return new Keys(slotPrefix + "principal:" + principal, slotPrefix + "source:" + source,
				slotPrefix + "principal-lease:" + principal);
	}

	private String digest(String namespace, String... values) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			mac.init(new SecretKeySpec(this.keySecret, HMAC_ALGORITHM));
			update(mac, namespace);
			for (String value : values) {
				mac.update(SEPARATOR);
				update(mac, value);
			}
			return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal());
		}
		catch (GeneralSecurityException exception) {
			throw new IllegalStateException("HmacSHA256 is not available", exception);
		}
	}

	private static void update(Mac mac, String value) {
		mac.update(value.getBytes(StandardCharsets.UTF_8));
	}

	record Keys(String principal, String source, String lease) {
	}

}
