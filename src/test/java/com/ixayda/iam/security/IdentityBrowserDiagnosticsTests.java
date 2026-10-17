package com.ixayda.iam.security;

import java.sql.SQLException;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.*;

class IdentityBrowserDiagnosticsTests {

	private IdentityBrowserLogCapture diagnostics;

	@BeforeEach
	void captureDiagnostics() {
		this.diagnostics = new IdentityBrowserLogCapture();
	}

	@AfterEach
	void stopCapture() {
		this.diagnostics.close();
	}

	@Test
	void correlatesFailuresWithoutLoggingRequestValuesOrExceptionMessages() {
		var request = new MockHttpServletRequest("POST", "/login");
		String untrusted = "secret-password-cookie-proof";
		request.addHeader("X-Request-ID", untrusted);
		request.addHeader("Cookie", untrusted);
		request.setParameter("password", untrusted);
		UUID correlation = IdentityBrowserDiagnostics.correlationId(request);
		var failure = new IllegalStateException(untrusted, new SQLException(untrusted, "23514"));
		IdentityBrowserDiagnostics.recordFailure(request, IdentityBrowserDiagnostics.Stage.AUTHENTICATION, failure);
		IdentityBrowserDiagnostics.recordFailure(request, IdentityBrowserDiagnostics.Stage.REQUEST_PROCESSING, failure);
		assertThat(IdentityBrowserDiagnostics.correlationId(request)).isEqualTo(correlation);
		assertThat(IdentityBrowserDiagnostics.correlationId(new MockHttpServletRequest())).isNotEqualTo(correlation);
		assertThat(this.diagnostics.events()).hasSize(2).allSatisfy(event -> {
			assertThat(event.getMessage().getFormattedMessage()).contains("correlationId=" + correlation,
					"exceptionType=java.lang.IllegalStateException", "causeType=java.sql.SQLException", "sqlState=23514")
					.doesNotContain(untrusted);
			assertThat(event.getThrown()).isNull();
		});
		assertThat(this.diagnostics.events().getFirst().getMessage().getFormattedMessage()).contains("stage=AUTHENTICATION");
		assertThat(this.diagnostics.events().getLast().getMessage().getFormattedMessage()).contains("stage=REQUEST_PROCESSING");
	}

	@ParameterizedTest
	@ValueSource(strings = { "secret\nforged-event", "123456", "28a00", "" })
	void ignoresMalformedSqlStates(String sqlState) {
		IdentityBrowserDiagnostics.recordFailure(new MockHttpServletRequest(),
				IdentityBrowserDiagnostics.Stage.ADMISSION, new SQLException("private", sqlState));
		assertThat(this.diagnostics.events()).singleElement().satisfies(event ->
				assertThat(event.getMessage().getFormattedMessage()).endsWith("sqlState=none").doesNotContain("private"));
	}

	@Test
	void cyclicExceptionChainsCannotPreventFailureHandling() {
		var first = new IllegalStateException("private");
		var second = new IllegalArgumentException("private", first);
		first.initCause(second);
		IdentityBrowserDiagnostics.recordFailure(new MockHttpServletRequest(),
				IdentityBrowserDiagnostics.Stage.REQUEST_PROCESSING, first);
		assertThat(this.diagnostics.events()).singleElement().satisfies(event ->
				assertThat(event.getMessage().getFormattedMessage()).contains("stage=REQUEST_PROCESSING").doesNotContain("private"));
	}

}
