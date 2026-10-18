package com.ixayda.iam.security;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import tools.jackson.databind.json.JsonMapper;

import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.*;

/** Shared TLS transport only; each feature test supplies its own accounts and assertions. */
abstract class BrowserHttpTestSupport {

	protected static final Path KEY_STORE = createKeyStore();

	@LocalServerPort
	protected int port;

	@DynamicPropertySource
	static void tls(DynamicPropertyRegistry properties) {
		properties.add("server.ssl.enabled", () -> true);
		properties.add("server.ssl.key-store", () -> KEY_STORE.toUri().toString());
		properties.add("server.ssl.key-store-password", () -> "test-store-password");
		properties.add("iam.password-authentication.cleanup-ms", () -> 3_600_000);
	}

	protected static void assertSecurityHeaders(HttpResponse<?> response) {
		assertThat(response.headers().firstValue("Strict-Transport-Security").orElseThrow()).contains("max-age=");
		assertThat(response.headers().firstValue("Content-Security-Policy").orElseThrow()).contains("frame-ancestors 'none'", "form-action 'self'");
		assertThat(response.headers().firstValue("X-Frame-Options")).contains("DENY");
		assertThat(response.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
		assertThat(response.headers().firstValue("Referrer-Policy")).contains("no-referrer");
		assertThat(response.headers().firstValue("Cache-Control").orElseThrow()).contains("no-store");
	}

	protected HttpResponse<String> get(HttpClient client, String path, String cookie) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20));
		if (cookie != null) { builder.header("Cookie", cookie); }
		return client.send(builder.GET().build(), HttpResponse.BodyHandlers.ofString());
	}

	protected HttpResponse<String> post(HttpClient client, String path, String cookie, String body) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20))
				.header("Content-Type", "application/x-www-form-urlencoded");
		if (cookie != null) { builder.header("Cookie", cookie); }
		return client.send(builder.POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
	}

	protected static String csrf(HttpResponse<String> response) {
		assertThat(response.statusCode()).as("CSRF token response").isEqualTo(200);
		var body = new JsonMapper().readTree(response.body());
		assertThat(body.path("headerName").asText()).isEqualTo("X-CSRF-TOKEN");
		return body.path("token").asText();
	}

	protected static String cookie(HttpResponse<String> response) {
		return response.headers().allValues("Set-Cookie").stream().filter(value -> value.startsWith("__Host-IAMSESSION="))
				.findFirst().orElseThrow().split(";", 2)[0];
	}

	protected static JsonRequest credentials(String username, String password, String csrf) {
		return new JsonRequest(new JsonMapper().writeValueAsString(Map.of("username", username, "password", password)), csrf);
	}

	protected record JsonRequest(String body, String csrfToken) { }

	protected HttpResponse<String> post(HttpClient client, String path, String cookie, JsonRequest request) throws Exception {
		var builder = HttpRequest.newBuilder(URI.create("https://localhost:" + this.port + path)).timeout(Duration.ofSeconds(20))
				.header("Content-Type", "application/json");
		if (cookie != null) { builder.header("Cookie", cookie); }
		if (request.csrfToken() != null) { builder.header("X-CSRF-TOKEN", request.csrfToken()); }
		return client.send(builder.POST(HttpRequest.BodyPublishers.ofString(request.body())).build(), HttpResponse.BodyHandlers.ofString());
	}

	protected static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }

	protected static HttpClient client() throws Exception {
		KeyStore store = KeyStore.getInstance("PKCS12");
		try (InputStream input = Files.newInputStream(KEY_STORE)) { store.load(input, "test-store-password".toCharArray()); }
		var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trust.init(store);
		SSLContext ssl = SSLContext.getInstance("TLS");
		ssl.init(null, trust.getTrustManagers(), null);
		return HttpClient.newBuilder().sslContext(ssl).followRedirects(HttpClient.Redirect.NEVER)
				.version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(10)).build();
	}

	protected static Path createKeyStore() {
		try {
			Path directory = Files.createTempDirectory("iam-test-tls-");
			Path store = directory.resolve("server.p12");
			Path log = directory.resolve("keytool.log");
			var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
					"-genkeypair", "-alias", "localhost", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
					"-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
					"-keystore", store.toString(), "-storepass", "test-store-password", "-noprompt")
					.redirectErrorStream(true).redirectOutput(log.toFile()).start();
			if (!process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) {
				process.destroyForcibly();
				throw new IllegalStateException("Test TLS certificate generation failed: " + Files.readString(log));
			}
			directory.toFile().deleteOnExit();
			log.toFile().deleteOnExit();
			store.toFile().deleteOnExit();
			return store;
		}
		catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
	}
}
