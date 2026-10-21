package com.ixayda.iam;

import java.io.InputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.function.LongFunction;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Starts the delivered executable against the fixture's restricted database identity and temporary TLS material. */
final class IdentityNativeAcceptanceRuntime implements AutoCloseable {

	private Process process;
	private final ProcessBuilder builder;
	private final HttpClient client;
	private final String origin;

	private IdentityNativeAcceptanceRuntime(ProcessBuilder builder, String origin, HttpClient client) throws Exception {
		this.builder = builder; this.process = builder.start(); this.origin = origin; this.client = client;
	}

	static IdentityNativeAcceptanceRuntime start(Path executable, Path directory, Map<String, Object> settings) throws Exception {
		if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
			throw new IllegalArgumentException("An executable native IAM artifact is required");
		}
		int port;
		try (var socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) { port = socket.getLocalPort(); }
		var properties = new Properties();
		settings.forEach((name, value) -> properties.setProperty(name, value.toString()));
		properties.setProperty("spring.main.web-application-type", "servlet");
		properties.setProperty("server.port", Integer.toString(port));
		Path configuration = privateFile(directory.resolve("native.properties"));
		try (var output = Files.newOutputStream(configuration)) { properties.store(output, null); }
		Path log = privateFile(directory.resolve("native.log"));
		var builder = processBuilder(executable, "--spring.config.additional-location=" + configuration.toUri());
		var client = client(properties);
		IdentityNativeAcceptanceRuntime runtime;
		try {
			String scheme = Boolean.parseBoolean(properties.getProperty("server.ssl.enabled", "false")) ? "https" : "http";
			runtime = new IdentityNativeAcceptanceRuntime(builder.redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile())), scheme + "://127.0.0.1:" + port, client);
		}
		catch (Exception ex) { client.close(); throw ex; }
		try { runtime.awaitReady(); return runtime; }
		catch (Exception ex) { runtime.terminate(); client.close(); throw ex; }
	}

	String origin() { return this.origin; }

	private static HttpClient client(Properties properties) throws Exception {
		boolean proxy = !Boolean.parseBoolean(properties.getProperty("server.ssl.enabled", "false"));
		var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2));
		if (!proxy) {
			var store = KeyStore.getInstance("PKCS12");
			try (InputStream input = Files.newInputStream(Path.of(URI.create(properties.getProperty("server.ssl.key-store"))))) {
				store.load(input, properties.getProperty("server.ssl.key-store-password").toCharArray());
			}
			var trust = KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null, null);
			trust.setCertificateEntry("fixture", store.getCertificate(store.aliases().nextElement()));
			var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); managers.init(trust);
			var tls = SSLContext.getInstance("TLS"); tls.init(null, managers.getTrustManagers(), null);
			client.sslContext(tls);
		}
		var cookies = new CookieManager();
		// This internal client represents the TLS proxy; browser checks still use real HTTPS.
		CookieHandler handler = new CookieHandler() {
			private URI external(URI uri) { return proxy ? URI.create("https" + uri.toString().substring("http".length())) : uri; }
			@Override public Map<String, List<String>> get(URI uri, Map<String, List<String>> headers) throws java.io.IOException { return cookies.get(external(uri), headers); }
			@Override public void put(URI uri, Map<String, List<String>> headers) throws java.io.IOException { cookies.put(external(uri), headers); }
		};
		return client.cookieHandler(handler).build();
	}

	private void awaitReady() throws Exception {
		var request = requestBuilder("/readyz").GET().build();
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
		while (System.nanoTime() < deadline) {
			if (!this.process.isAlive()) { throw new IllegalStateException("Native IAM exited before readiness"); }
			try { if (this.client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode() == 200) { return; } }
			catch (java.io.IOException ex) { /* The Web listener may not have started yet. */ }
			Thread.sleep(100);
		}
		throw new IllegalStateException("Native IAM readiness timed out");
	}

	static void verifyStartupRejections(Path executable, Path directory, Map<String, Object> settings, String ownerPassword) throws Exception {
		for (String command : List.of("migrate", "initialize-signing-key", "bootstrap-admin", "recover-admin", "recover-admin-credentials",
				"rotate-signing-key", "compromise-signing-key", "recover-signing-key", "quarantine-restore", "recover-restored-admin", "release-restore",
				"preview-protocol-cleanup", "cleanup-protocol-state")) {
			Path log = privateFile(directory.resolve("rejected-" + command + ".log"));
			var process = processBuilder(executable, command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
			requireRejected(process);
			if (!Files.readString(log).contains("use the JVM JAR for maintenance commands")) {
				throw new IllegalStateException("Native maintenance command did not fail at its entry boundary");
			}
		}
		int index = 0;
		var invalidSettings = List.of(
				new RejectedSettings(Map.of("server.forward-headers-strategy", "NATIVE", "server.tomcat.remoteip.internal-proxies", ""), "NATIVE forwarded headers require an explicit proxy allowlist"),
				new RejectedSettings(Map.of("server.forward-headers-strategy", "FRAMEWORK"), "IAM supports NONE or NATIVE forwarded headers"),
				new RejectedSettings(Map.of("iam.protocol.issuer", "http://iam.invalid"), "An explicit HTTPS issuer at the root path is required"),
				new RejectedSettings(Map.of("iam.protocol.issuer", ""), "An explicit HTTPS issuer at the root path is required"),
				new RejectedSettings(Map.of("iam.protocol.issuer", "https://iam.invalid/tenant"), "An explicit HTTPS issuer at the root path is required"),
				new RejectedSettings(Map.of("iam.protocol.identity-frontend-uri", "https://other.invalid/identity"), "A fixed same-origin HTTPS identity frontend URI is required"),
				new RejectedSettings(Map.of("iam.protocol.identity-frontend-uri", ""), "A fixed same-origin HTTPS identity frontend URI is required"),
				new RejectedSettings(Map.of("iam.signing.key-file", ""), "Signing requires an external protection key"),
				new RejectedSettings(Map.of("iam.authorization.key-file", ""), "Protocol persistence requires external protection keys"),
				new RejectedSettings(Map.of("spring.datasource.username", "acceptance_owner", "spring.datasource.password", ownerPassword,
						"iam.database.restricted-runtime", "false"), "IAM runtime database identity has maintenance capabilities"));
		for (var invalid : invalidSettings) {
			var properties = new Properties(); settings.forEach((name, value) -> properties.setProperty(name, value.toString()));
			properties.setProperty("spring.main.web-application-type", "servlet"); properties.putAll(invalid.overrides());
			Path configuration = privateFile(directory.resolve("rejected-" + index + ".properties"));
			try (var output = Files.newOutputStream(configuration)) { properties.store(output, null); }
			Path log = privateFile(directory.resolve("rejected-" + index++ + ".log"));
			requireRejected(processBuilder(executable, "--spring.config.additional-location=" + configuration.toUri())
					.redirectErrorStream(true).redirectOutput(log.toFile()).start());
			if (!Files.readString(log).contains(invalid.reason())) { throw new IllegalStateException("Native startup failed for an unexpected reason"); }
		}
	}

	private record RejectedSettings(Map<String, String> overrides, String reason) { }

	private static void requireRejected(Process process) throws Exception {
		try {
			if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() == 0) {
				throw new IllegalStateException("Invalid native startup was not rejected");
			}
		}
		finally { if (process.isAlive()) { process.destroyForcibly(); process.waitFor(); } }
	}

	void verifySessionRestart(Map<String, Object> fixture, LongFunction<String> otp, boolean documentation) throws Exception {
		String keys = request("/oauth2/jwks", null, null, 200).body();
		request("/v3/api-docs", null, null, 401);
		request("/v3/api-docs.yaml", null, null, 401);
		var json = new JsonMapper();
		request("/login", json.writeValueAsString(Map.of("username", fixture.get("adminUsername"), "password", fixture.get("adminPassword"))), "application/json", 204);
		long step;
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(65);
		do {
			long now = System.currentTimeMillis(); step = now / 30000;
			if (step > (long) fixture.get("adminTotpUsedStep") && now % 30000 < 27000) { break; }
			if (System.nanoTime() >= deadline) { throw new IllegalStateException("Fresh native acceptance TOTP step timed out"); }
			Thread.sleep(100);
		} while (true);
		String code = otp.apply(step);
		request("/admin/mfa", "code=" + code, "application/x-www-form-urlencoded", 204);
		fixture.put("adminTotpUsedStep", TotpTestSupport.latestMatchingStep(otp, step, System.currentTimeMillis() / 30000));
		request("/api/admin/me", null, null, 200);
		stopCleanly(); this.process = this.builder.start(); awaitReady();
		var administrator = json.readTree(request("/api/admin/me", null, null, 200).body());
		if (!administrator.path("id").asString().equals(fixture.get("adminId").toString())
				|| !keys.equals(request("/oauth2/jwks", null, null, 200).body())) {
			throw new IllegalStateException("Native restart did not preserve administrator evidence and signing identity");
		}
		var specification = request("/v3/api-docs", null, null, documentation ? 200 : 404);
		if (documentation) {
			var paths = json.readTree(specification.body()).path("paths");
			if (!paths.has("/login") || !paths.has("/api/me") || !paths.has("/oauth2/token") || !paths.has("/readyz")) {
				throw new IllegalStateException("Native OpenAPI specification is incomplete");
			}
		}
		request("/v3/api-docs.yaml", null, null, documentation ? 200 : 404);
		for (String path : List.of("/v3/api-docs/swagger-config", "/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/swagger-ui-bundle.js")) {
			request(path, null, null, 403);
		}
		request("/logout", "", "application/x-www-form-urlencoded", 204);
		request("/api/me", null, null, 401);
		request("/v3/api-docs", null, null, 401);
		request("/v3/api-docs.yaml", null, null, 401);
	}

	private HttpResponse<String> request(String path, String body, String contentType, int status) throws Exception {
		var request = requestBuilder(path);
		if (body == null) { request.GET(); }
		else {
			var csrfResponse = this.client.send(requestBuilder("/api/csrf").GET().build(), HttpResponse.BodyHandlers.ofString());
			if (csrfResponse.statusCode() != 200) { throw new IllegalStateException("Native lifecycle CSRF request failed"); }
			JsonNode csrf = new JsonMapper().readTree(csrfResponse.body());
			request.header(csrf.path("headerName").asString(), csrf.path("token").asString()).header("Content-Type", contentType)
					.POST(HttpRequest.BodyPublishers.ofString(body));
		}
		var response = this.client.send(request.build(), HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != status) { throw new IllegalStateException("Native lifecycle request failed: " + path + " (" + response.statusCode() + ")"); }
		return response;
	}

	private HttpRequest.Builder requestBuilder(String path) {
		var request = HttpRequest.newBuilder(URI.create(this.origin + path)).timeout(Duration.ofSeconds(5));
		if (this.origin.startsWith("http:")) { request.header("X-Forwarded-Proto", "https").header("X-Forwarded-For", "127.0.0.1"); }
		return request;
	}

	private static ProcessBuilder processBuilder(Path executable, String argument) {
		var builder = new ProcessBuilder(executable.toAbsolutePath().toString(), "-XX:MissingRegistrationReportingMode=Exit", argument);
		builder.environment().keySet().removeIf(name -> name.matches("(?:SPRING_|SERVER_|IAM_|MANAGEMENT_|LOGGING_).*|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS"));
		return builder;
	}

	private static Path privateFile(Path path) throws Exception {
		return Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
	}

	private void terminate() throws InterruptedException {
		this.process.destroy();
		if (!this.process.waitFor(15, TimeUnit.SECONDS)) { this.process.destroyForcibly(); this.process.waitFor(); }
	}

	private void stopCleanly() throws InterruptedException {
		if (!this.process.isAlive()) { throw new IllegalStateException("Native IAM exited during acceptance"); }
		terminate();
		if (this.process.exitValue() != 0 && this.process.exitValue() != 143) {
			throw new IllegalStateException("Native IAM did not shut down cleanly");
		}
	}

	@Override
	public void close() throws Exception {
		try { stopCleanly(); }
		finally { this.client.close(); }
	}
}
