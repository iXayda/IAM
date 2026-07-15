package com.ixayda.iam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;

class IamCoreServiceApplicationTests extends ApplicationIntegrationTest {

	@LocalServerPort
	private int port;

	@Test
	void startsWebServerAndExposesObservabilityEndpoints() throws Exception {
		HttpClient client = HttpClient.newHttpClient();

		assertThat(status(client, "/actuator/health")).isEqualTo(200);
		assertThat(status(client, "/actuator/health/readiness")).isEqualTo(200);
		assertThat(status(client, "/actuator/prometheus")).isEqualTo(200);
	}

	private int status(HttpClient client, String path) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + path))
			.GET()
			.build();
		return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
	}

}
