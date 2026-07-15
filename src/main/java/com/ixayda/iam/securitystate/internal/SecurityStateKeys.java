package com.ixayda.iam.securitystate.internal;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.ixayda.iam.securitystate.SecurityStateKey;
import com.ixayda.iam.securitystate.SecurityStateToken;

final class SecurityStateKeys {

	private static final String HMAC_ALGORITHM = "HmacSHA256";

	private static final byte[] SEPARATOR = { 0 };

	private final byte[] keySecret;

	private final String keyPrefix;

	SecurityStateKeys(byte[] keySecret, String keyPrefix) {
		this.keySecret = keySecret.clone();
		this.keyPrefix = keyPrefix;
	}

	String encode(SecurityStateKey key, SecurityStateToken token) {
		return this.keyPrefix + ":" + digest(key.tenantId().value().toString(), key.purpose(), key.binding(),
				token.value());
	}

	private String digest(String... values) {
		try {
			Mac mac = Mac.getInstance(HMAC_ALGORITHM);
			mac.init(new SecretKeySpec(this.keySecret, HMAC_ALGORITHM));
			update(mac, "one-time-security-state");
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

}
