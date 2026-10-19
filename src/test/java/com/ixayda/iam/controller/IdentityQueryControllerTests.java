package com.ixayda.iam.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import com.ixayda.iam.model.IdentityUser;
import com.ixayda.iam.model.IdentityUserPage;
import com.ixayda.iam.model.SecurityAuditPage;
import com.ixayda.iam.service.IdentityAdministratorSessions;
import com.ixayda.iam.service.IdentityUserCreations;
import com.ixayda.iam.service.IdentityUserProfileManagement;
import com.ixayda.iam.service.IdentityUserStateChanges;
import com.ixayda.iam.service.IdentityUsers;
import com.ixayda.iam.service.SecurityAudits;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.BindException;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class IdentityQueryControllerTests {

	private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

	@ParameterizedTest
	@MethodSource("invalidRequests")
	void malformedReadsAreRejectedBeforeAnyServiceAccessAndKeepTheExistingErrorResponse(Route route, String violation) throws Exception {
		var endpoint = endpoint(route);
		long length = violation.equals("known-length-body") ? 1 : violation.equals("zero-length-body") ? 0 : -1;
		var request = request(route, length, violation.equals("read-failure"));
		if (violation.endsWith("body")) { request.setContent("private-request-body".getBytes(StandardCharsets.UTF_8)); }
		if (violation.equals("transfer-encoding")) { request.addHeader("Transfer-Encoding", "chunked"); }
		if (violation.equals("unknown-parameter")) { request.addParameter("unexpected", "value"); }
		if (violation.equals("duplicate-parameter")) { request.addParameter("pageSize", "1", "2"); }

		endpoint.mvc().perform(context -> request).andExpect(status().isBadRequest())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
				.andExpect(content().string(route.error))
				.andExpect(result -> assertThat(result.getResolvedException()).isInstanceOfAny(IllegalArgumentException.class, BindException.class));
		verifyNoInteractions(endpoint.services());
	}

	@ParameterizedTest
	@MethodSource("routes")
	void emptyKnownAndUnknownLengthReadsReachTheirActualSearchOrDetailService(Route route) throws Exception {
		for (long length : new long[] { 0, -1 }) {
			var endpoint = endpoint(route);
			endpoint.mvc().perform(context -> request(route, length, false)).andExpect(status().isOk())
					.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
			assertThat(mockingDetails(endpoint.services()[0]).getInvocations()).hasSize(1);
			if (endpoint.services().length > 1) { verifyNoInteractions(Arrays.copyOfRange(endpoint.services(), 1, endpoint.services().length)); }
		}
	}

	private static Stream<Route> routes() { return Arrays.stream(Route.values()); }

	private static Stream<Arguments> invalidRequests() {
		return routes().flatMap(route -> Stream.of("unknown-length-body", "zero-length-body", "known-length-body", "transfer-encoding",
				"unknown-parameter", "duplicate-parameter", "read-failure").map(violation -> Arguments.of(route, violation)));
	}

	private static MockHttpServletRequest request(Route route, long length, boolean readFailure) {
		var request = new MockHttpServletRequest("GET", route.path) {
			@Override public long getContentLengthLong() { return length; }
			@Override public int getContentLength() { return (int) length; }
			@Override public ServletInputStream getInputStream() {
				if (!readFailure) { return super.getInputStream(); }
				return new ServletInputStream() {
					@Override public int read() throws IOException { throw new IOException("synthetic request stream failure"); }
					@Override public boolean isFinished() { return false; }
					@Override public boolean isReady() { return true; }
					@Override public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
				};
			}
		};
		request.setServletPath(route.path); request.setSecure(true);
		return request;
	}

	private static Endpoint endpoint(Route route) {
		var administrators = mock(IdentityAdministratorSessions.class);
		return switch (route) {
			case USERS, USER -> {
				var service = mock(IdentityUsers.class); var creations = mock(IdentityUserCreations.class);
				var profiles = mock(IdentityUserProfileManagement.class); var states = mock(IdentityUserStateChanges.class);
				when(service.search(isNull(), isNull(), eq(20), isNull())).thenReturn(new IdentityUserPage(List.of(), null));
				when(service.findById(ID)).thenReturn(Optional.of(new IdentityUser(ID, "alice", "Alice", IdentityUser.Status.ACTIVE, Instant.EPOCH)));
				yield endpoint(new IdentityUserManagementController(service, creations, profiles, states, administrators), service, creations, profiles, states, administrators);
			}
			case AUDITS -> {
				var service = mock(SecurityAudits.class);
				when(service.search(any(), eq(20), isNull())).thenReturn(new SecurityAuditPage(List.of(), null));
				yield endpoint(new SecurityAuditController(service), service);
			}
		};
	}

	private static Endpoint endpoint(Object controller, Object... services) {
		return new Endpoint(MockMvcBuilders.standaloneSetup(controller).build(), services);
	}

	private record Endpoint(MockMvc mvc, Object[] services) { }

	private enum Route {
		USERS("/api/admin/users", "Invalid user request"),
		USER("/api/admin/users/" + ID, "Invalid user request"),
		AUDITS("/api/admin/audits", "Invalid audit query");

		private final String path;
		private final String error;
		Route(String path, String error) { this.path = path; this.error = error; }
	}

}
