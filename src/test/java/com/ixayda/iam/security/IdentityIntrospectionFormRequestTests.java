package com.ixayda.iam.security;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.*;

class IdentityIntrospectionFormRequestTests {

	@Test
	void acceptsTheFullTokenBudgetAndPreservesDuplicatesForTheEndpointToReject() throws Exception {
		var request = form("token=" + "a".repeat(16384) + "&token_type_hint=access_token&token_type_hint=other");
		var bounded = new IdentityIntrospectionFormRequest(request);
		assertThat(bounded.getParameter("token")).hasSize(16384);
		assertThat(bounded.getParameterValues("token_type_hint")).containsExactly("access_token", "other");
	}

	@Test
	void actualBodyLimitAppliesWithoutAContentLength() {
		var request = form("token=" + "a".repeat(20481));
		assertThatThrownBy(() -> new IdentityIntrospectionFormRequest(request)).isInstanceOf(IdentityIntrospectionFormRequest.TooLargeException.class);
	}

	@Test
	void malformedPercentEncodingIsAnOrdinaryBadRequest() {
		assertThatThrownBy(() -> new IdentityIntrospectionFormRequest(form("token=%zz"))).isInstanceOf(IllegalArgumentException.class);
	}

	private MockHttpServletRequest form(String body) {
		var request = new MockHttpServletRequest("POST", "/oauth2/introspect") {
			@Override public long getContentLengthLong() { return -1; }
		};
		request.setContentType("application/x-www-form-urlencoded"); request.setContent(body.getBytes(StandardCharsets.UTF_8)); return request;
	}
}
