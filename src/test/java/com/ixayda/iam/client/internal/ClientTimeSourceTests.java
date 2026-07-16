package com.ixayda.iam.client.internal;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ClientTimeSourceTests {

	@Test
	void matchesPostgreSqlTimestampPrecision() {
		assertThat(new ClientTimeSource().now().getNano() % 1_000).isZero();
	}

}
