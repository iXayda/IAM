package com.ixayda.iam;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministrators;
import com.ixayda.iam.service.IdentityClients;
import com.ixayda.iam.service.IdentityResourceCredentials;
import com.ixayda.iam.service.IdentityResourceRoles;
import com.ixayda.iam.service.IdentityResources;
import com.ixayda.iam.service.IdentityUserRoles;
import com.ixayda.iam.service.IdentityUserSetups;
import com.ixayda.iam.service.IdentityUsers;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import tools.jackson.databind.json.JsonMapper;

/** Disposable browser fixture. Only this test process holds owner credentials; no production artifact includes it. */
public final class IdentityAcceptanceFixture {

	private IdentityAcceptanceFixture() { }

	public static void main(String[] args) {
		try {
			if (args.length < 3) { throw new IllegalArgumentException("Invalid acceptance arguments"); }
			Path executable = null; boolean documentation = false; boolean proxy = false;
			for (int i = 3; i < args.length; i++) {
				if (args[i].equals("--proxy") && !proxy) { proxy = true; }
				else if (args[i].equals("--documentation") && !documentation) { documentation = true; }
				else if (!args[i].startsWith("--") && executable == null) { executable = Path.of(args[i]); }
				else { throw new IllegalArgumentException("Invalid acceptance arguments"); }
			}
			if (documentation && executable == null) { throw new IllegalArgumentException("Documentation acceptance requires the native artifact"); }
			run(Path.of(args[0]), args[1], args[2], executable, documentation, proxy);
		}
		catch (Exception ex) { System.err.println("Isolated acceptance fixture failed"); System.exit(1); }
	}

	private static void run(Path directory, String issuer, String suite, Path executable, boolean documentation, boolean proxy) throws Exception {
		if (!Set.of("accounts", "application-a", "application-b", "oidc", "mfa").contains(suite)) {
			throw new IllegalArgumentException("Unknown acceptance suite");
		}
		if (!issuer.matches("https://127\\.0\\.0\\.1:[0-9]{1,5}")) { throw new IllegalArgumentException("Loopback fixture issuer is required"); }
		if (!Files.isDirectory(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)
				|| !Files.getPosixFilePermissions(directory).equals(PosixFilePermissions.fromString("rwx------"))) {
			throw new IllegalArgumentException("Private acceptance directory is required");
		}
		var random = new SecureRandom();
		var properties = new HashMap<String, Object>();
		properties.put("spring.main.banner-mode", "off"); properties.put("spring.datasource.hikari.maximum-pool-size", 4);
		properties.put("spring.datasource.hikari.minimum-idle", 0);
		properties.put("spring.profiles.active", ""); properties.put("spring.flyway.enabled", true);
		properties.put("iam.database.restricted-runtime", false);
		properties.put("iam.signing.key-file", secretFile(directory, "signing.key", 32, random).toString());
		properties.put("iam.totp.key-file", secretFile(directory, "totp.key", 32, random).toString());
		properties.put("iam.authorization.key-file", secretFile(directory, "authorization.key", 64, random).toString());
		properties.put("iam.protocol.issuer", issuer); properties.put("iam.protocol.identity-frontend-uri", issuer + "/identity");
		String ownerPassword = UUID.randomUUID().toString(); String runtimePassword = UUID.randomUUID().toString();
		try (var postgres = new PostgreSQLContainer("postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873")
				.withPassword(UUID.randomUUID().toString())) {
			postgres.start();
			try (var connection = DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword()); var sql = connection.createStatement()) {
				sql.execute("CREATE ROLE acceptance_owner LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + ownerPassword + "'");
				sql.execute("CREATE ROLE acceptance_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + runtimePassword + "'");
				sql.execute("CREATE DATABASE acceptance OWNER acceptance_owner");
			}
			String url = "jdbc:postgresql://" + postgres.getHost() + ":" + postgres.getMappedPort(5432) + "/acceptance";
			properties.put("spring.datasource.url", url); properties.put("spring.datasource.username", "acceptance_owner"); properties.put("spring.datasource.password", ownerPassword);
			String adminPassword = "harbor violet orchard lighthouse " + UUID.randomUUID();
			var result = new HashMap<String, Object>();
			try (var owner = start(properties, WebApplicationType.NONE)) {
				owner.getBean(com.ixayda.iam.service.IdentitySigningKeys.class).initializeForInstallation();
				var administrators = owner.getBean(IdentityAdministrators.class);
				var audit = new SecurityAuditContext("deployment:acceptance", "deployment:fixture", UUID.randomUUID());
				var id = administrators.createCandidate("acceptance-admin", "Acceptance administrator", adminPassword, audit);
				var authentication = new TotpAuthenticationContext("deployment:fixture", java.net.InetAddress.getLoopbackAddress(), UUID.randomUUID());
				var enrollment = administrators.prepareCandidate(id, adminPassword, authentication).orElseThrow().enrollment().orElseThrow();
				long step = Instant.now().getEpochSecond() / 30;
				var codes = administrators.bootstrap(id, enrollment.factorId(), adminPassword, otp(enrollment.secret(), step), authentication).orElseThrow();
				result.put("adminId", id); result.put("adminUsername", "acceptance-admin"); result.put("adminPassword", adminPassword);
				result.put("adminTotpSecret", enrollment.secret()); result.put("adminRecoveryCodes", codes.codes());
				result.put("adminTotpUsedStep", owner.getBean(JdbcClient.class).sql("SELECT last_used_step FROM iam_user_totp WHERE user_id=:id AND factor_id=:factorId")
						.param("id", id).param("factorId", enrollment.factorId()).query(Long.class).single());
				prepareScenario(owner, suite, result, audit);
			}
			postgres.copyFileToContainer(MountableFile.forHostPath(Path.of("deploy/postgresql/grant-runtime.sql")), "/tmp/grant-runtime.sql");
			var granted = postgres.execInContainer("psql", "-X", "-U", "acceptance_owner", "-d", "acceptance", "-v", "runtime_role=acceptance_runtime", "-v", "iam_schema=public", "-f", "/tmp/grant-runtime.sql");
			if (granted.getExitCode() != 0) { throw new IllegalStateException("Acceptance runtime grants failed"); }
			String tlsPassword = UUID.randomUUID().toString(); Path store = keyStore(directory, tlsPassword); KeyStore keys = KeyStore.getInstance("PKCS12");
			try (InputStream input = Files.newInputStream(store)) { keys.load(input, tlsPassword.toCharArray()); }
			String alias = keys.aliases().nextElement();
			Path certificate = protectedFile(directory.resolve("tls-cert.pem"), pem("CERTIFICATE", keys.getCertificate(alias).getEncoded()));
			Path privateKey = protectedFile(directory.resolve("tls-key.pem"), pem("PRIVATE KEY", keys.getKey(alias, tlsPassword.toCharArray()).getEncoded()));
			properties.put("server.address", "127.0.0.1"); properties.put("server.port", 0); properties.put("server.ssl.enabled", !proxy);
			if (proxy) {
				properties.put("server.forward-headers-strategy", "NATIVE");
				properties.put("server.tomcat.remoteip.internal-proxies", "127\\.0\\.0\\.1");
			}
			if (!proxy) {
				properties.put("server.ssl.key-store", store.toUri().toString()); properties.put("server.ssl.key-store-password", tlsPassword);
			}
			properties.put("spring.datasource.username", "acceptance_runtime"); properties.put("spring.datasource.password", runtimePassword);
			properties.put("spring.profiles.active", documentation ? "runtime,documentation" : "runtime");
			properties.put("spring.flyway.enabled", false); properties.put("iam.database.restricted-runtime", true);
			result.put("issuer", issuer); result.put("certificate", certificate.toString()); result.put("privateKey", privateKey.toString());
			if (executable == null) {
				try (var runtime = start(properties, WebApplicationType.SERVLET)) {
					int port = ((WebServerApplicationContext) runtime).getWebServer().getPort();
					awaitBrowser(directory, result, (proxy ? "http" : "https") + "://127.0.0.1:" + port);
				}
			}
			else {
				if (suite.equals("accounts")) {
					IdentityNativeAcceptanceRuntime.verifyStartupRejections(executable, directory, properties, ownerPassword);
				}
				try (var runtime = IdentityNativeAcceptanceRuntime.start(executable, directory, properties)) {
					if (suite.equals("accounts")) {
						runtime.verifySessionRestart(result, step -> otp((String) result.get("adminTotpSecret"), step), documentation);
					}
					awaitBrowser(directory, result, runtime.origin());
				}
			}
		}
	}

	private static void awaitBrowser(Path directory, Map<String, Object> result, String backend) throws Exception {
		result.put("backend", backend);
		protectedFile(directory.resolve("fixture.json"), new JsonMapper().writeValueAsBytes(result));
		System.out.println("Isolated acceptance fixture ready");
		System.in.read();
	}

	private static void prepareScenario(ConfigurableApplicationContext owner, String suite, Map<String, Object> result,
			SecurityAuditContext audit) throws Exception {
		if (suite.equals("accounts")) { return; }
		var user = owner.getBean(IdentityUsers.class).create("browser-user", "Browser user", audit);
		var setups = owner.getBean(IdentityUserSetups.class);
		String password = "orchard amber bridge ocean " + UUID.randomUUID();
		var proof = setups.issue(user.id(), audit);
		setups.complete(user.id(), proof.token(), password, audit.source(), audit.correlationId());
		result.put("user", Map.of("id", user.id(), "username", user.username(), "password", password));
		if (suite.equals("oidc")) {
			result.put("applications", List.of(
					prepareApplication(owner, user.id(), "a", "127.0.0.2", "127.0.0.4", audit),
					prepareApplication(owner, user.id(), "b", "127.0.0.3", "127.0.0.5", audit)));
		}
	}

	private static Map<String, Object> prepareApplication(ConfigurableApplicationContext owner, UUID userId, String name,
			String rpHost, String apiHost, SecurityAuditContext audit) throws Exception {
		String origin = freeOrigin(rpHost), apiOrigin = freeOrigin(apiHost);
		var resource = owner.getBean(IdentityResources.class).create("orders-" + name, "Orders " + name, audit);
		var role = owner.getBean(IdentityResourceRoles.class).create(resource.id(), "reader", "Reader", audit);
		owner.getBean(IdentityUserRoles.class).change(userId, role.id(), 0, true, audit);
		var client = owner.getBean(IdentityClients.class).create(new IdentityClientConfiguration("Application " + name,
				resource.id(), List.of(origin + "/callback"), Set.of("openid", "profile", "offline_access"), Set.of(role.id())), audit);
		var validator = owner.getBean(IdentityResourceCredentials.class).rotateSecret(resource.id(), 0, audit);
		return Map.of("name", name, "origin", origin, "apiOrigin", apiOrigin, "audience", resource.audience(),
				"resourceId", resource.id(), "roleId", role.id(), "clientId", client.client().id(),
				"clientSecret", client.secret(), "validationSecret", validator.secret());
	}

	private static String freeOrigin(String host) throws Exception {
		try (var socket = new ServerSocket(0, 0, InetAddress.getByName(host))) {
			return "https://" + host + ":" + socket.getLocalPort();
		}
	}

	private static ConfigurableApplicationContext start(Map<String, Object> properties, WebApplicationType type) {
		var environment = new StandardEnvironment();
		properties.put("spring.main.web-application-type", type.name());
		environment.getPropertySources().addFirst(new MapPropertySource("isolatedAcceptance", new HashMap<>(properties)));
		return new SpringApplicationBuilder(IamApplication.class).environment(environment).web(type).run();
	}

	private static Path secretFile(Path directory, String name, int size, SecureRandom random) throws Exception {
		byte[] value = new byte[size]; random.nextBytes(value); return protectedFile(directory.resolve(name), value);
	}
	private static Path keyStore(Path directory, String password) throws Exception {
		Path store = directory.resolve("tls.p12");
		var builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
				"-genkeypair", "-alias", "loopback", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2", "-dname", "CN=localhost",
				"-ext", "SAN=dns:localhost,ip:127.0.0.1,ip:127.0.0.2,ip:127.0.0.3,ip:127.0.0.4,ip:127.0.0.5", "-storetype", "PKCS12",
				"-keystore", store.toString(), "-storepass:env", "IAM_ACCEPTANCE_TLS_PASSWORD", "-noprompt");
		builder.environment().put("IAM_ACCEPTANCE_TLS_PASSWORD", password);
		Path log = protectedFile(directory.resolve("keytool.log"), new byte[0]);
		var process = builder.redirectErrorStream(true).redirectOutput(log.toFile()).start();
		if (!process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IllegalStateException("TLS generation timed out"); }
		if (process.exitValue() != 0) { throw new IllegalStateException("TLS generation failed"); }
		Files.setPosixFilePermissions(store, PosixFilePermissions.fromString("rw-------")); return store;
	}
	private static Path protectedFile(Path file, byte[] value) throws Exception {
		Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
		return Files.write(file, value);
	}
	private static byte[] pem(String type, byte[] encoded) {
		return ("-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(encoded)
				+ "\n-----END " + type + "-----\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
	}
	private static String otp(String secret, long step) {
		byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(step).array();
		var hmac = new HMac(new SHA1Digest()); hmac.init(new KeyParameter(Base32.decode(secret))); hmac.update(counter, 0, counter.length);
		byte[] hash = new byte[20]; hmac.doFinal(hash, 0); int position = hash[19] & 15;
		return String.format(java.util.Locale.ROOT, "%06d", (java.nio.ByteBuffer.wrap(hash, position, 4).getInt() & 0x7fffffff) % 1_000_000);
	}
}
