package com.ixayda.iam;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class IamCoreServiceApplicationTests {

	@LocalServerPort
	private int port;

	@Test
	void startsWebServer() throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.port + "/"))
			.GET()
			.build();

		HttpResponse<Void> response = HttpClient.newHttpClient()
			.send(request, HttpResponse.BodyHandlers.discarding());

		assertThat(response.statusCode()).isEqualTo(404);
	}

}
