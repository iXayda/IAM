package com.ixayda.iam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;

class IamCoreServiceApplicationTests extends ApplicationIntegrationTest {

	@LocalServerPort
	private int port;

	@Autowired
	private Tracer tracer;

	@Test
	void startsWebServerAndExposesObservabilityEndpoints() throws Exception {
		HttpClient client = HttpClient.newHttpClient();

		assertThat(status(client, "/actuator/health")).isEqualTo(200);
		assertThat(status(client, "/actuator/health/readiness")).isEqualTo(200);
		assertThat(status(client, "/livez")).isEqualTo(200);
		assertThat(status(client, "/readyz")).isEqualTo(200);
		assertThat(status(client, "/actuator/prometheus")).isEqualTo(200);
	}

	@Test
	void publishesHttpLatencyBucketsWithStableTags() throws Exception {
		HttpClient client = HttpClient.newHttpClient();
		assertThat(status(client, "/livez")).isEqualTo(200);

		String metrics = body(client, "/actuator/prometheus");

		assertThat(metrics).contains("http_server_requests_seconds_bucket")
			.contains("application=\"iam-core-service\"")
			.contains("environment=\"test\"")
			.contains("le=\"0.1\"");
	}

	@Test
	void correlatesLogsWithTheCurrentTrace() {
		Span span = this.tracer.nextSpan().name("log-correlation-test").start();
		try (Tracer.SpanInScope ignored = this.tracer.withSpan(span)) {
			assertThat(MDC.get("traceId")).isEqualTo(span.context().traceId());
			assertThat(MDC.get("spanId")).isEqualTo(span.context().spanId());
		}
		finally {
			span.end();
		}
	}

	private int status(HttpClient client, String path) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + path))
			.GET()
			.build();
		return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
	}

	private String body(HttpClient client, String path) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + path))
			.GET()
			.build();
		return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
	}

}
