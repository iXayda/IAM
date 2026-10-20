package com.ixayda.iam.security;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import com.ixayda.iam.service.IdentityBrowserSessions;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityBrowserBoundaryFilterTests {

	@Test
	void rejectsPlainHttpEvenWhenForwardedHeadersClaimHttps() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		var filter = new IdentityBrowserBoundaryFilter(sessions, 100, 8, headers());
		var request = request();
		request.setSecure(false);
		request.addHeader("X-Forwarded-Proto", "https");
		var response = new MockHttpServletResponse();
		filter.doFilter(request, response, (req, res) -> fail("Plain HTTP must not enter the session chain"));
		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
		assertThat(response.getHeaders("Set-Cookie")).isEmpty();
		verifyNoInteractions(sessions);
	}

	@Test
	void boundsGlobalWorkAndPersistsAnEntryThrottleEvent() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		var filter = new IdentityBrowserBoundaryFilter(sessions, 100, 1, headers());
		var entered = new CountDownLatch(1);
		var release = new CountDownLatch(1);
		try (var executor = Executors.newSingleThreadExecutor()) {
			var running = executor.submit(() -> {
				filter.doFilter(request(), new MockHttpServletResponse(), (req, res) -> {
					entered.countDown();
					try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
					catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IOException(ex); }
				});
				return true;
			});
			try {
				assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
				var response = new MockHttpServletResponse();
				filter.doFilter(request(), response, (req, res) -> fail("Concurrent request was admitted"));
				assertThat(response.getStatus()).isEqualTo(429);
				assertThat(response.getHeader("Retry-After")).isEqualTo("1");
				verify(sessions).recordEntryThrottle();
			}
			finally { release.countDown(); }
			assertThat(running.get(10, TimeUnit.SECONDS)).isTrue();
		}
		var recovered = new MockHttpServletResponse();
		filter.doFilter(request(), recovered, (req, res) -> res.getWriter().write("available"));
		assertThat(recovered.getContentAsString()).isEqualTo("available");
	}

	@Test
	void rateLimitAlsoBoundsSequentialRequests() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		var filter = new IdentityBrowserBoundaryFilter(sessions, 1, 8, headers(), () -> 1_000_000_000L);
		var statuses = new java.util.ArrayList<Integer>();
		for (int i = 0; i < 10; i++) {
			var response = new MockHttpServletResponse();
			filter.doFilter(request(), response, (req, res) -> res.getWriter().write("available"));
			statuses.add(response.getStatus());
		}
		assertThat(statuses).contains(200, 429);
		verify(sessions, atLeastOnce()).recordEntryThrottle();
	}

	@Test
	void admissionAuditFailureCannotTurnIntoAnUnauditedRateDenial() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		doThrow(new IllegalStateException("injected failure")).when(sessions).recordEntryThrottle();
		var filter = new IdentityBrowserBoundaryFilter(sessions, 1, 8, headers(), () -> 1_000_000_000L);
		var responses = new java.util.ArrayList<Integer>();
		for (int i = 0; i < 10; i++) {
			var response = new MockHttpServletResponse();
			filter.doFilter(request(), response, (req, res) -> res.getWriter().write("available"));
			responses.add(response.getStatus());
		}
		assertThat(responses).contains(503).doesNotContain(429);
		verify(sessions, atLeast(2)).recordEntryThrottle();
	}

	@Test
	void blockedThrottleAuditDoesNotBlockAdmissionAndDoesNotStartDuplicateAudits() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		var auditEntered = new CountDownLatch(1);
		var releaseAudit = new CountDownLatch(1);
		doAnswer(invocation -> {
			auditEntered.countDown();
			assertThat(releaseAudit.await(10, TimeUnit.SECONDS)).isTrue();
			return null;
		}).when(sessions).recordEntryThrottle();
		var now = new AtomicLong(1_000_000_000L);
		var filter = new IdentityBrowserBoundaryFilter(sessions, 1, 1, headers(), now::get);
		filter.doFilter(request(), new MockHttpServletResponse(), (req, res) -> { });
		try (var executor = Executors.newFixedThreadPool(2)) {
			var denied = new MockHttpServletResponse();
			var auditing = executor.submit(() -> {
				filter.doFilter(request(), denied, (req, res) -> fail("Rate-limited request admitted"));
				return true;
			});
			try {
				assertThat(auditEntered.await(10, TimeUnit.SECONDS)).isTrue();
				var pending = new MockHttpServletResponse();
				var next = executor.submit(() -> {
					filter.doFilter(request(), pending, (req, res) -> fail("Rate-limited request admitted"));
					return true;
				});
				assertThat(next.get(2, TimeUnit.SECONDS)).isTrue();
				assertThat(pending.getStatus()).isEqualTo(503);
				assertThat(pending.getHeader("Retry-After")).isNull();
				// A new window has a free permit even while the previous audit is blocked.
				now.addAndGet(1_000_000_000L);
				var healthy = new MockHttpServletResponse();
				var admitted = executor.submit(() -> {
					filter.doFilter(request(), healthy, (req, res) -> res.getWriter().write("available"));
					return true;
				});
				assertThat(admitted.get(2, TimeUnit.SECONDS)).isTrue();
				assertThat(healthy.getContentAsString()).isEqualTo("available");
				var secondWindow = new MockHttpServletResponse();
				filter.doFilter(request(), secondWindow, (req, res) -> fail("Rate-limited request admitted"));
				assertThat(secondWindow.getStatus()).isEqualTo(503);
				verify(sessions).recordEntryThrottle();
			}
			finally { releaseAudit.countDown(); }
			assertThat(auditing.get(10, TimeUnit.SECONDS)).isTrue();
			assertThat(denied.getStatus()).isEqualTo(429);
		}
		// Completing the previous window's audit cannot cover a newer window.
		var response = new MockHttpServletResponse();
		filter.doFilter(request(), response, (req, res) -> fail("Rate-limited request admitted"));
		assertThat(response.getStatus()).isEqualTo(429);
		verify(sessions, times(2)).recordEntryThrottle();
	}

	@Test
	void failedThrottleAuditCanBeRetriedAndOnlyDurableAuditAllows429() throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		doThrow(new IllegalStateException("injected failure")).doNothing().when(sessions).recordEntryThrottle();
		var filter = new IdentityBrowserBoundaryFilter(sessions, 1, 1, headers(), () -> 1_000_000_000L);
		filter.doFilter(request(), new MockHttpServletResponse(), (req, res) -> { });
		for (int status : new int[] { 503, 429, 429 }) {
			var response = new MockHttpServletResponse();
			filter.doFilter(request(), response, (req, res) -> fail("Rate-limited request admitted"));
			assertThat(response.getStatus()).isEqualTo(status);
		}
		verify(sessions, times(2)).recordEntryThrottle();
	}

	@ParameterizedTest
	@ValueSource(ints = { 0, 1, 2, 3, 4, 5, 6 })
	void everyRedirectAndFlushVariantCanBeWithdrawnOnCommitFailure(int variant) throws Exception {
		var filter = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 8, headers());
		var actual = new MockHttpServletResponse();
		filter.doFilter(request(), actual, (req, res) -> {
			var response = (HttpServletResponse) res;
			response.setHeader("Set-Cookie", "__Host-IAMSESSION=uncommitted; Secure; Path=/");
			response.getWriter().write("private profile");
			switch (variant) {
				case 0 -> response.sendRedirect("/api/me");
				case 1 -> response.sendRedirect("/api/me", false);
				case 2 -> response.sendRedirect("/api/me", 303);
				case 3 -> response.sendRedirect("/api/me", 303, false);
				case 4 -> response.flushBuffer();
				case 5 -> response.getWriter().flush();
				case 6 -> response.getOutputStream().flush();
				default -> throw new AssertionError();
			}
			assertThat(actual.isCommitted()).isFalse();
			throw new IllegalStateException("injected commit failure");
		});
		assertThat(actual.getStatus()).isEqualTo(503);
		assertThat(actual.getHeaders("Set-Cookie")).isEmpty();
		assertThat(actual.getHeader("Location")).isNull();
		assertThat(actual.getContentAsString()).contains("\"code\":\"SERVICE_UNAVAILABLE\"");
	}

	@ParameterizedTest
	@ValueSource(ints = { 429, 503 })
	void securityHeaderPolicyCoversAdmissionDenialsAndAuditFailures(int status) throws Exception {
		var sessions = mock(IdentityBrowserSessions.class);
		if (status == 503) {
			doThrow(new IllegalStateException("injected audit failure")).when(sessions).recordEntryThrottle();
		}
		var boundary = new IdentityBrowserBoundaryFilter(sessions, 1, 1, headers(), () -> 1_000_000_000L);
		boundary.doFilter(request(), new MockHttpServletResponse(), (req, res) -> { });
		var response = new MockHttpServletResponse();
		boundary.doFilter(request(), response, (req, res) -> fail("Rate-limited request admitted"));
		assertThat(response.getStatus()).isEqualTo(status);
		assertThat(response.getHeader("Strict-Transport-Security")).contains("max-age=");
		assertThat(response.getHeader("Content-Security-Policy")).contains("frame-ancestors 'none'");
		assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
		assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
	}

	@Test
	void oversizedResponsesDoNotLeakTruncatedContentOrCookies() throws Exception {
		var filter = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 8, headers());
		var response = new MockHttpServletResponse();
		filter.doFilter(request(), response, (req, res) -> {
			((HttpServletResponse) res).setHeader("Set-Cookie", "uncommitted");
			res.getWriter().write("x".repeat(131_073));
		});
		assertThat(response.getStatus()).isEqualTo(503);
		assertThat(response.getHeaders("Set-Cookie")).isEmpty();
		assertThat(response.getContentAsString()).contains("\"code\":\"SERVICE_UNAVAILABLE\"");
	}

	@ParameterizedTest
	@ValueSource(strings = { "/api/me", "/swagger-ui/swagger-ui-bundle.js", "/v3/api-docs", "/v3/api-docs.yaml", "/v3/api-docs-other" })
	void boundsOpenApiResponsesSeparatelyFromIdentityResponses(String path) throws Exception {
		var filter = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 8, headers());
		var request = request();
		request.setServletPath(path);
		var response = new MockHttpServletResponse();
		filter.doFilter(request, response, (req, res) -> res.getOutputStream().write(new byte[1_600_000]));
		if (path.equals("/v3/api-docs") || path.equals("/v3/api-docs.yaml")) {
			assertThat(response.getStatus()).isEqualTo(200);
			assertThat(response.getContentAsByteArray()).hasSize(1_600_000);
		}
		else {
			assertThat(response.getStatus()).isEqualTo(503);
			assertThat(response.getContentAsString()).contains("\"code\":\"SERVICE_UNAVAILABLE\"");
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "stream", "writer" })
	void downstreamCannotPublishSuccessAfterCatchingAndResettingAnOverflow(String output) throws Exception {
		var filter = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 8, headers());
		var actual = new MockHttpServletResponse();
		filter.doFilter(request(), actual, (req, res) -> {
			if (output.equals("stream")) {
				try { res.getOutputStream().write(new byte[131_073]); }
				catch (IOException ignored) { /* MVC may classify this as a disconnected client. */ }
			}
			else {
				res.getWriter().write("x".repeat(131_073));
				res.getWriter().flush();
				assertThat(res.getWriter().checkError()).isTrue();
			}
			res.reset();
			((HttpServletResponse) res).setStatus(200);
			res.getWriter().write("misleading success");
		});
		assertThat(actual.getStatus()).isEqualTo(503);
		assertThat(actual.getContentAsString()).contains("\"code\":\"SERVICE_UNAVAILABLE\"").doesNotContain("misleading success");
	}

	@Test
	void oversizedOpenApiResponsesAreWithdrawnWithoutCookies() throws Exception {
		var filter = new IdentityBrowserBoundaryFilter(mock(IdentityBrowserSessions.class), 100, 8, headers());
		var request = request();
		request.setServletPath("/v3/api-docs");
		var response = new MockHttpServletResponse();
		filter.doFilter(request, response, (req, res) -> {
			((HttpServletResponse) res).setHeader("Set-Cookie", "uncommitted");
			res.getOutputStream().write(new byte[2_097_153]);
		});
		assertThat(response.getStatus()).isEqualTo(503);
		assertThat(response.getHeaders("Set-Cookie")).isEmpty();
		assertThat(response.getContentAsString()).contains("\"code\":\"SERVICE_UNAVAILABLE\"");
	}

	private static HeaderWriter headers() {
		return new IdentityBrowserConfiguration().browserSecurityHeaders();
	}

	private static MockHttpServletRequest request() {
		var request = new MockHttpServletRequest("GET", "/login");
		request.setSecure(true);
		return request;
	}
}
