package com.ixayda.iam.service;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import com.ixayda.iam.model.IdentityAdministratorAuthentication;
import com.ixayda.iam.repository.IdentityAdministratorRepository;
import com.ixayda.iam.repository.IdentityBrowserSessionRepository;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityAdministratorSessionsTests {

	@ParameterizedTest(name = "password={0}ms, MFA={1}ns from now: current={2}")
	@CsvSource({"0, 0, true", "0, 1, false", "0, -1, false", "1, 0, false",
			"-900000, -899999999999, true", "-900000, -900000000000, false"})
	void checksPasswordChronologyAndExactMfaLifetime(long passwordOffsetMillis, long mfaOffsetNanos, boolean current) {
		var clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC);
		var userId = UUID.randomUUID();
		var factorId = UUID.randomUUID();
		var administrators = mock(IdentityAdministratorRepository.class);
		when(administrators.hasCurrentAuthentication(userId, factorId, 1L)).thenReturn(true);
		var sessions = new IdentityAdministratorSessions(administrators, mock(IdentityBrowserSessionRepository.class),
				mock(SecurityAudits.class), clock);
		long passwordTime = clock.millis() + passwordOffsetMillis;
		var evidence = new IdentityAdministratorAuthentication(userId, factorId, 1L, passwordTime, clock.instant().plusNanos(mfaOffsetNanos));
		assertThat(sessions.authorities(userId, passwordTime, evidence)).hasSize(current ? 3 : 0);
	}

}
