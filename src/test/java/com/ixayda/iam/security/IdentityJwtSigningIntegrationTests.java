package com.ixayda.iam.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.credential.SigningKeySecrets;
import com.ixayda.iam.model.IdentitySigningKey;
import com.ixayda.iam.repository.IdentitySigningKeyRepository;
import com.ixayda.iam.service.IdentitySigningKeys;
import com.ixayda.iam.service.SecurityAudits;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@Import(PostgreSqlTestConfiguration.class)
class IdentityJwtSigningIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final JWKSelector ALL = new JWKSelector(new JWKMatcher.Builder().build());
	@Autowired private IdentityJwtEncoder encoder;
	@Autowired private IdentityJwkSource source;
	@Autowired private IdentitySigningKeys keys;
	@Autowired private SecurityAudits audits;
	@Autowired private JdbcClient jdbc;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private IdentitySigningKey key;

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) { registry.add("iam.signing.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		reset();
		this.key = this.keys.initialize().orElseThrow();
	}

	@ParameterizedTest
	@ValueSource(strings = { "JWT", "at+jwt" })
	void officialEncodingUsesThePersistentIdentityAndBothSupportedTypesVerifyWithItsPublicKey(String type) throws Exception {
		var before = snapshot();
		var parameters = JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).type(type).build(), claims());
		var token = encode(parameters);
		assertThat(token.getHeaders()).containsEntry("alg", SignatureAlgorithm.RS256).containsEntry("kid", this.key.id().toString()).containsEntry("typ", type);
		var verified = decode(token);
		assertThat(verified.getHeaders()).containsEntry("alg", "RS256").containsEntry("kid", this.key.id().toString()).containsEntry("typ", type);
		assertThat(verified.getClaims()).containsEntry("sub", parameters.getClaims().getSubject()).containsEntry("scope", "openid profile");
		var publicKeys = this.source.get(ALL, null);
		assertThat(publicKeys).hasSize(1);
		var publicKey = publicKeys.getFirst();
		assertThat(publicKey.getKeyID()).isEqualTo(this.key.id().toString());
		assertThat(publicKey.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
		assertThat(publicKey.isPrivate()).isFalse();
		assertThat(publicKey.toJSONObject()).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi", "oth", "k");
		assertThat(publicKey.toRSAKey().toRSAPublicKey()).isEqualTo(this.key.publicKey());
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void defaultHeadersAndAnExplicitCurrentKidUseTheSameIdentity() {
		var first = encode(JwtEncoderParameters.from(claims()));
		var second = encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).keyId(this.key.id().toString()).build(), claims()));
		assertThat(first.getHeaders()).containsEntry("typ", "JWT").containsEntry("kid", this.key.id().toString());
		assertThat(second.getHeaders()).containsEntry("typ", "JWT").containsEntry("kid", this.key.id().toString());
		decode(first); decode(second);
	}

	@Test
	void encodingRequiresAnExistingWriteTransactionWithoutChangingTheIndependentReadContract() {
		var before = snapshot();
		assertUnavailable(() -> this.encoder.encode(JwtEncoderParameters.from(claims())));
		assertThatThrownBy(this.keys::lockForIssuance).isInstanceOf(IllegalStateException.class);
		var readOnly = new TransactionTemplate(this.transactions); readOnly.setReadOnly(true);
		assertUnavailable(() -> readOnly.execute(tx -> this.encoder.encode(JwtEncoderParameters.from(claims()))));
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> assertThatThrownBy(this.keys::signingMaterial).isInstanceOf(IllegalStateException.class));
		assertThat(this.keys.signingMaterial().key()).isEqualTo(this.key);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "RS512", "HS256", "none", "type", "kid", "jwk", "jku", "crit" })
	void callersCannotChangeTheAlgorithmKeyOrHeaderTrustPolicy(String invalid) {
		var header = JwsHeader.with(SignatureAlgorithm.RS256);
		switch (invalid) {
			case "RS512", "HS256", "none" -> header.header("alg", invalid);
			case "type" -> header.type("private-unsupported-type");
			case "kid" -> header.keyId(UUID.randomUUID().toString());
			case "jwk" -> header.jwk(Map.of("kty", "oct", "k", "private-signing-value"));
			case "jku" -> header.header("jku", "https://private-key.example/jwks");
			default -> header.header("crit", List.of("private-critical-value"));
		}
		var before = snapshot();
		var parameters = JwtEncoderParameters.from(header.build(), claims());
		assertUnavailable(() -> encode(parameters));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void oversizedResultsAndMalformedClaimsNeverLeakTheirValuesThroughFailures() {
		var before = snapshot();
		assertUnavailable(() -> this.encoder.encode(null));
		assertUnavailable(() -> encode(JwtEncoderParameters.from(JwtClaimsSet.from(claims()).claim("large", "private-oversized-".repeat(2000)).build())));
		assertUnavailable(() -> encode(JwtEncoderParameters.from(JwtClaimsSet.from(claims()).claim("iat", "private-incorrect-time").build())));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void missingInitializationCannotGenerateATemporaryKeyAndUnknownSelectorsNeverChooseAnotherKey() throws Exception {
		assertThat(this.source.get(new JWKSelector(new JWKMatcher.Builder().keyID(UUID.randomUUID().toString()).build()), null)).isEmpty();
		assertThat(this.source.get(new JWKSelector(new JWKMatcher.Builder().algorithm(JWSAlgorithm.HS256).build()), null)).isEmpty();
		reset();
		var before = snapshot();
		assertThat(this.source.get(ALL, null)).isEmpty();
		assertUnavailable(() -> encode(JwtEncoderParameters.from(claims())));
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void theOfficialDecoderCannotAcceptAnUnknownKidEvenWithAnOtherwiseValidSignature() {
		var material = this.keys.signingMaterial();
		String unknown = UUID.randomUUID().toString();
		var nativeEncoder = NimbusJwtEncoder.withKeyPair(material.key().publicKey(), (RSAPrivateKey) material.privateKey())
				.algorithm(SignatureAlgorithm.RS256).jwkPostProcessor(builder -> builder.keyID(unknown)).build();
		var token = nativeEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).keyId(unknown).build(), claims()));
		assertThatThrownBy(() -> decode(token)).isInstanceOf(BadJwtException.class);
	}

	@Test
	void privateMaterialIsReloadedAfterEveryCallWhilePublicReadsSurvivePrivateCorruption() throws Exception {
		var first = encode(JwtEncoderParameters.from(claims()));
		this.jdbc.sql("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)").update();
		var before = snapshot();
		assertUnavailable(() -> encode(JwtEncoderParameters.from(claims())));
		assertThat(this.source.get(ALL, null)).hasSize(1).allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
		decode(first);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void restartAfterRotationUsesTheSameCurrentKidAndRetainsThePreviousPublicIdentity() {
		var previous = this.key;
		this.key = this.keys.rotate(previous.id(), new com.ixayda.iam.model.SecurityAuditContext("deployment:operator", "deployment:signing-rotation:CHANGE-123", UUID.randomUUID()));
		var before = snapshot();
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(), "spring.datasource.password", this.postgres.getPassword(),
				"iam.signing.key-file", KEY_FILE.toString(), "spring.main.banner-mode", "off")).run()) {
			var reloaded = new IdentityJwtEncoder(restarted.getBean(IdentitySigningKeys.class));
			var template = new TransactionTemplate(restarted.getBean(PlatformTransactionManager.class));
			var token = template.execute(tx -> reloaded.encode(JwtEncoderParameters.from(claims())));
			assertThat(token.getHeaders()).containsEntry("kid", this.key.id().toString());
			decode(token);
			assertThat(restarted.getBean(IdentitySigningKeys.class).verificationKeys()).containsExactly(previous, this.key);
			assertThat(restarted.getBeansOfType(IdentityJwtEncoder.class)).isEmpty();
			assertThat(restarted.getBeansOfType(IdentityJwkSource.class)).isEmpty();
		}
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void theSigningLockRemainsHeldUntilTheOuterIssuanceTransactionCommits() throws Exception {
		var signed = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var signing = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
				var token = this.encoder.encode(JwtEncoderParameters.from(claims()));
				signed.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { throw new IllegalStateException(ex); }
				return token;
			}));
			try {
				assertThat(signed.await(10, TimeUnit.SECONDS)).isTrue();
				var update = executor.submit(() -> this.jdbc.sql("UPDATE iam_signing_key_state SET initialized_at=initialized_at /* signing_lock_probe */").update());
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%signing_lock_probe%'").query(Long.class).single() > 0);
				assertThat(update.isDone()).isFalse();
				release.countDown();
				decode(signing.get(10, TimeUnit.SECONDS));
				assertThat(update.get(10, TimeUnit.SECONDS)).isEqualTo(1);
			}
			finally { release.countDown(); }
		}
	}

	@Test
	void concurrentSignersShareTheLifecycleLockWithoutWaitingForEachOtherToCommit() throws Exception {
		var inside = new CountDownLatch(1); var release = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> new TransactionTemplate(this.transactions).execute(tx -> {
				var token = this.encoder.encode(JwtEncoderParameters.from(claims())); inside.countDown();
				try { assertThat(release.await(10, TimeUnit.SECONDS)).isTrue(); }
				catch (InterruptedException ex) { throw new IllegalStateException(ex); }
				return token;
			}));
			try {
				assertThat(inside.await(10, TimeUnit.SECONDS)).isTrue();
				var second = executor.submit(() -> encode(JwtEncoderParameters.from(claims())));
				decode(second.get(5, TimeUnit.SECONDS));
				assertThat(first.isDone()).isFalse();
			}
			finally { release.countDown(); }
			decode(first.get(10, TimeUnit.SECONDS));
		}
	}

	@Test
	void aSignerWaitingOnLifecycleReadsTheChangedPrivateRecordAfterTheWait() throws Exception {
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			connection.setAutoCommit(false);
			try (var lock = connection.prepareStatement("SELECT singleton FROM iam_signing_key_state FOR UPDATE")) { lock.executeQuery().close(); }
			var signing = executor.submit(() -> { assertUnavailable(() -> encode(JwtEncoderParameters.from(claims()))); return true; });
			try {
				await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT initial_key_id%FROM iam_signing_key_state%FOR SHARE'").query(Long.class).single() > 0);
				try (var tamper = connection.prepareStatement("UPDATE iam_signing_key SET encrypted_private_key=set_byte(encrypted_private_key,10,get_byte(encrypted_private_key,10) # 1)")) { tamper.executeUpdate(); }
			}
			finally { connection.commit(); }
			assertThat(signing.get(10, TimeUnit.SECONDS)).isTrue();
		}
	}

	@Test
	void publicJwkSelectionWorksWithoutPrivateColumnPermissionsOrProtectionKeys() throws Exception {
		this.keys.rotate(this.key.id(), new com.ixayda.iam.model.SecurityAuditContext("deployment:operator", "deployment:signing-rotation:CHANGE-123", UUID.randomUUID()));
		String role = "jwk_reader_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE ROLE " + role + " NOLOGIN").update();
		try {
			this.jdbc.sql("GRANT USAGE ON SCHEMA public TO " + role).update();
			this.jdbc.sql("GRANT SELECT (id,algorithm,public_key,created_at,status,verification_until) ON iam_signing_key TO " + role).update();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
					var context = new AnnotationConfigApplicationContext()) {
				JdbcClient reader = JdbcClient.create(new SingleConnectionDataSource(connection, true)); reader.sql("SET ROLE " + role).update();
				context.registerBean(JdbcClient.class, () -> reader); context.registerBean(SigningKeySecrets.class, () -> new SigningKeySecrets(""));
				context.registerBean(SecurityAudits.class, () -> this.audits); context.registerBean(PlatformTransactionManager.class, () -> this.transactions);
				context.register(IdentitySigningKeyRepository.class, IdentitySigningKeys.class); context.refresh();
				var source = new IdentityJwkSource(context.getBean(IdentitySigningKeys.class));
				assertThat(source.get(ALL, null)).hasSize(2).allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
				this.jdbc.sql("REVOKE SELECT(public_key) ON iam_signing_key FROM " + role).update();
				assertThatThrownBy(() -> source.get(ALL, null)).isInstanceOf(KeySourceException.class).hasMessage("Public signing keys are unavailable").hasNoCause();
			}
		}
		finally { this.jdbc.sql("DROP OWNED BY " + role).update(); this.jdbc.sql("DROP ROLE " + role).update(); }
	}

	private Jwt encode(JwtEncoderParameters parameters) { return new TransactionTemplate(this.transactions).execute(tx -> this.encoder.encode(parameters)); }
	private Jwt decode(Jwt token) {
		var decoder = NimbusJwtDecoder.withJwkSource(this.source).jwsAlgorithm(SignatureAlgorithm.RS256)
				.jwtProcessorCustomizer(processor -> processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT"), new JOSEObjectType("at+jwt")))).build();
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(Duration.ofSeconds(30)), new JwtIssuerValidator("https://issuer.example")));
		return decoder.decode(token.getTokenValue());
	}
	private static JwtClaimsSet claims() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		return JwtClaimsSet.builder().issuer("https://issuer.example").subject(UUID.randomUUID().toString()).audience(List.of("urn:example:orders"))
				.issuedAt(now).expiresAt(now.plusSeconds(300)).claim("scope", "openid profile").build();
	}
	private static void assertUnavailable(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
		assertThatThrownBy(action).isInstanceOf(JwtEncodingException.class).hasMessage("Token signing is unavailable").hasNoCause();
	}
	private void reset() {
		this.jdbc.sql("TRUNCATE iam_restore_release,iam_signing_key,iam_signing_key_state,iam_security_audit").update();
		this.jdbc.sql("INSERT INTO iam_signing_key_state(singleton) VALUES(1)").update();
	}
	private List<List<String>> snapshot() {
		return List.of("iam_signing_key", "iam_signing_key_state", "iam_security_audit").stream()
				.map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
	}
	private static Path keyFile() {
		try { Path file = Files.createTempFile("iam-jwt-signing-test-", ".key"); byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes); Files.write(file, bytes); file.toFile().deleteOnExit(); return file; }
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}

}
