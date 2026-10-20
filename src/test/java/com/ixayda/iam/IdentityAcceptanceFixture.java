package com.ixayda.iam;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.ixayda.iam.model.SecurityAuditContext;
import com.ixayda.iam.model.TotpAuthenticationContext;
import com.ixayda.iam.service.IdentityAdministrators;

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
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import tools.jackson.databind.json.JsonMapper;

/** Disposable browser fixture. Only this test process holds owner credentials; no production artifact includes it. */
public final class IdentityAcceptanceFixture {

	private IdentityAcceptanceFixture() { }

	public static void main(String[] args) {
		try {
			if (args.length < 2 || args.length > 3 || args.length == 3 && !args[2].equals("--proxy")) {
				throw new IllegalArgumentException("Invalid acceptance arguments");
			}
			run(Path.of(args[0]), args[1], args.length == 3);
		}
		catch (Exception ex) { System.err.println("Isolated acceptance fixture failed"); System.exit(1); }
	}

	private static void run(Path directory, String issuer, boolean proxy) throws Exception {
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
				var codes = administrators.bootstrap(id, enrollment.factorId(), adminPassword, otp(enrollment.secret()), authentication).orElseThrow();
				result.put("adminId", id); result.put("adminUsername", "acceptance-admin"); result.put("adminPassword", adminPassword);
				result.put("adminTotpSecret", enrollment.secret()); result.put("adminRecoveryCodes", codes.codes());
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
			properties.put("spring.profiles.active", "runtime");
			properties.put("spring.flyway.enabled", false); properties.put("iam.database.restricted-runtime", true);
			try (var runtime = start(properties, WebApplicationType.SERVLET)) {
				int port = ((WebServerApplicationContext) runtime).getWebServer().getPort();
				result.put("issuer", issuer); result.put("backend", (proxy ? "http" : "https") + "://127.0.0.1:" + port);
				result.put("certificate", certificate.toString()); result.put("privateKey", privateKey.toString());
				protectedFile(directory.resolve("fixture.json"), new JsonMapper().writeValueAsBytes(result));
				System.out.println("Isolated acceptance fixture ready");
				while (System.in.read() != -1) { break; }
			}
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
	private static String otp(String secret) {
		long step = Instant.now().getEpochSecond() / 30 - 1;
		byte[] counter = java.nio.ByteBuffer.allocate(8).putLong(step).array();
		var hmac = new HMac(new SHA1Digest()); hmac.init(new KeyParameter(Base32.decode(secret))); hmac.update(counter, 0, counter.length);
		byte[] hash = new byte[20]; hmac.doFinal(hash, 0); int position = hash[19] & 15;
		return String.format(java.util.Locale.ROOT, "%06d", (java.nio.ByteBuffer.wrap(hash, position, 4).getInt() & 0x7fffffff) % 1_000_000);
	}
}
