package com.ixayda.iam.security;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Map;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.tomcat.autoconfigure.TomcatServerProperties;
import org.springframework.boot.tomcat.autoconfigure.TomcatWebServerFactoryCustomizer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServer;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/** Real connector and Boot proxy configuration, without database or business fixtures. */
final class TransportHttpTestSupport implements AutoCloseable {

	private final WebServer server;
	private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

	TransportHttpTestSupport(Map<String, String> settings, Filter boundary) throws Exception {
		this(settings, boundary, false);
	}

	TransportHttpTestSupport(Map<String, String> settings, Filter boundary, boolean environmentVariables) throws Exception {
		var environment = new MockEnvironment().withProperty("server.tomcat.remoteip.host-header", "").withProperty("server.tomcat.remoteip.port-header", "");
		if (environmentVariables) { environment.getPropertySources().addFirst(new SystemEnvironmentPropertySource("proxy-test", new java.util.HashMap<>(settings))); }
		else { settings.forEach(environment::setProperty); }
		var factory = new TomcatServletWebServerFactory(0);
		factory.setAddress(InetAddress.getByName("127.0.0.1"));
		new IdentityTransportConfiguration().transportPolicy(environment).customize(factory);
		var binder = Binder.get(environment);
		new TomcatWebServerFactoryCustomizer(environment,
				binder.bind("server", ServerProperties.class).orElseGet(ServerProperties::new),
				binder.bind("server.tomcat", TomcatServerProperties.class).orElseGet(TomcatServerProperties::new), new WebProperties()).customize(factory);
		this.server = factory.getWebServer(context -> {
			context.addFilter("boundary", boundary).addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");
			context.addServlet("probe", new HttpServlet() {
				@Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
					response.getWriter().write(request.getRemoteAddr() + "|" + request.isSecure() + "|" + request.getServerName());
				}
			}).addMapping("/*");
		});
		this.server.start();
	}

	HttpResponse<String> get(String path, Map<String, String> headers) throws Exception {
		var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + this.server.getPort() + path)).timeout(Duration.ofSeconds(5)).GET();
		headers.forEach(request::header);
		return this.client.send(request.build(), HttpResponse.BodyHandlers.ofString());
	}

	@Override public void close() { try { this.client.close(); } finally { this.server.stop(); this.server.destroy(); } }
}
