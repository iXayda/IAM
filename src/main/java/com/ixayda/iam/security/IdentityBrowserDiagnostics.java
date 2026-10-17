package com.ixayda.iam.security;

import java.sql.SQLException;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Operational diagnostics without request values, exception messages or bound SQL parameters. */
final class IdentityBrowserDiagnostics {

	private static final Logger LOGGER = LoggerFactory.getLogger(IdentityBrowserDiagnostics.class);
	private static final String CORRELATION_ID = IdentityBrowserDiagnostics.class.getName() + ".correlationId";

	private IdentityBrowserDiagnostics() {
	}

	static UUID correlationId(HttpServletRequest request) {
		if (request.getAttribute(CORRELATION_ID) instanceof UUID existing) {
			return existing;
		}
		UUID generated = UUID.randomUUID();
		request.setAttribute(CORRELATION_ID, generated);
		return generated;
	}

	static void recordFailure(HttpServletRequest request, Stage stage, Throwable failure) {
		Throwable cause = failure;
		String sqlState = "none";
		// Bound traversal even if a dependency supplies a cyclic exception chain.
		for (int depth = 0; depth < 8; depth++) {
			if (cause instanceof SQLException sql && sql.getSQLState() != null
					&& sql.getSQLState().matches("[A-Z0-9]{5}")) {
				sqlState = sql.getSQLState();
			}
			if (cause.getCause() == null || cause.getCause() == cause || depth == 7) {
				break;
			}
			cause = cause.getCause();
		}
		LOGGER.error("event=browser_failure correlationId={} stage={} exceptionType={} causeType={} sqlState={}",
				correlationId(request), stage, failure.getClass().getName(), cause.getClass().getName(), sqlState);
	}

	enum Stage {
		ADMISSION, AUTHENTICATION, REQUEST_PROCESSING, RESPONSE_PUBLICATION
	}

}
