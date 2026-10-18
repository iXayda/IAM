package com.ixayda.iam.controller;

import java.io.IOException;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

final class IdentityQueryRequests {

	private IdentityQueryRequests() { }

	static void require(HttpServletRequest request, Set<String> allowed, String errorMessage) {
		if (request.getContentLengthLong() > 0 || request.getHeader("Transfer-Encoding") != null
				|| !allowed.containsAll(request.getParameterMap().keySet())
				|| request.getParameterMap().values().stream().anyMatch(values -> values.length != 1)) {
			throw new IllegalArgumentException(errorMessage);
		}
		try {
			if (request.getInputStream().read() != -1) { throw new IllegalArgumentException(errorMessage); }
		}
		catch (IOException ex) { throw new IllegalArgumentException(errorMessage, ex); }
	}

}
