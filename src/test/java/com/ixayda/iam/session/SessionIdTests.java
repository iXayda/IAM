package com.ixayda.iam.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.Test;

class SessionIdTests {

	private static final UUID VALUE = UUID.fromString("019bc1e7-14d1-7d38-bd23-0877f2cd0e35");

	@Test
	void createsUuidBackedSessionIds() {
		SessionId sessionId = new SessionId(VALUE);

		assertThat(SessionId.from(sessionId.toString())).isEqualTo(sessionId);
		assertThat(SessionId.random().value()).isNotNull();
	}

	@Test
	void rejectsNullValues() {
		assertThatThrownBy(() -> new SessionId(null)).isInstanceOf(NullPointerException.class);
		assertThatThrownBy(() -> SessionId.from(null)).isInstanceOf(NullPointerException.class);
	}

}
