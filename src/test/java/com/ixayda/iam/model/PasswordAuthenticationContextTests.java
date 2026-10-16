package com.ixayda.iam.model;

import java.net.InetAddress;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class PasswordAuthenticationContextTests {

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", "internal:test\n", "来源", "bad/source" })
	void rejectsUntrustedSourceIdentifiers(String source) {
		assertThatIllegalArgumentException().isThrownBy(() -> new PasswordAuthenticationContext(source, InetAddress.getLoopbackAddress(), UUID.randomUUID()));
	}

	@Test
	void requiresTheVerifiedPeerAndCorrelationId() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PasswordAuthenticationContext("internal:test", null, UUID.randomUUID()));
		assertThatIllegalArgumentException().isThrownBy(() -> new PasswordAuthenticationContext("internal:test", InetAddress.getLoopbackAddress(), null));
	}

}
