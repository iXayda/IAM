package com.ixayda.iam.service;

import java.security.Principal;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import com.ixayda.iam.IamApplication;
import com.ixayda.iam.PostgreSqlTestConfiguration;
import com.ixayda.iam.model.IdentityClientConfiguration;
import com.ixayda.iam.model.SecurityAuditContext;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.ixayda.iam.PostgreSqlMigrationTestSupport.copyRows;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(PostgreSqlTestConfiguration.class)
class IdentityAuthorizationsIntegrationTests {

	private static final Path KEY_FILE = keyFile();
	private static final SecurityAuditContext SYSTEM = new SecurityAuditContext("system:authorization-test", "internal:test", UUID.randomUUID());
	private static final List<String> TABLES = List.of("oauth2_authorization", "iam_authorization_record", "iam_authorization_token_index");
	@Autowired private IdentityAuthorizations authorizations;
	@Autowired private IdentityClients clients;
	@Autowired private IdentityResources resources;
	@Autowired private IdentityUsers users;
	@Autowired private JdbcClient jdbc;
	@Autowired private JdbcTemplate template;
	@Autowired private PlatformTransactionManager transactions;
	@Autowired private PostgreSQLContainer postgres;
	private UUID userId;
	private RegisteredClient client;

	@DynamicPropertySource
	static void key(DynamicPropertyRegistry properties) { properties.add("iam.authorization.key-file", KEY_FILE::toString); }

	@BeforeEach
	void clean() {
		this.jdbc.sql("TRUNCATE oauth2_registered_client,iam_user,iam_resource,iam_security_audit CASCADE").update();
		this.jdbc.sql("INSERT INTO iam_admin_bootstrap(singleton) VALUES (1)").update();
		this.userId = this.users.create("alice", "Alice", SYSTEM).id();
		UUID resource = this.resources.create("urn:example:orders", "Orders", SYSTEM).id();
		var created = this.clients.create(new IdentityClientConfiguration("Orders", resource, List.of("https://orders.example/callback"), Set.of("openid", "profile", "offline_access"), Set.of()), SYSTEM);
		this.client = new JdbcRegisteredClientRepository(this.template).findById(created.client().id().toString());
	}

	@AfterEach
	void removeFaultsAndRecords() {
		for (String table : TABLES) { this.jdbc.sql("DROP TRIGGER IF EXISTS authorization_test_fault ON " + table).update(); }
		this.jdbc.sql("DROP FUNCTION IF EXISTS authorization_test_fault()").update();
		this.jdbc.sql("TRUNCATE oauth2_authorization CASCADE").update();
	}

	@Test
	void officialSerializationRoundTripsEverySupportedTokenAndProtectsAttributesAndMetadataAsWellAsValues() {
		var original = authorization();
		var saved = this.authorizations.save(original, 0);
		assertThat(saved.version()).isEqualTo(1);
		assertThat(saved.authorization()).isEqualTo(original);
		assertThat(saved.toString()).doesNotContain("token", "private", original.getId());
		assertThat(this.authorizations.findById(UUID.fromString(original.getId()))).contains(saved);
		for (var token : Map.of("state", original.<String>getAttribute(OAuth2ParameterNames.STATE), "code", original.getToken(OAuth2AuthorizationCode.class).getToken().getTokenValue(),
				"access_token", original.getAccessToken().getToken().getTokenValue(), "id_token", original.getToken(OidcIdToken.class).getToken().getTokenValue(), "refresh_token", original.getRefreshToken().getToken().getTokenValue()).entrySet()) {
			assertThat(this.authorizations.findByToken(token.getValue(), token.getKey())).contains(saved);
			assertThat(this.authorizations.findByToken(token.getValue(), null)).contains(saved);
		}
		var raw = this.jdbc.sql("SELECT * FROM oauth2_authorization WHERE id=:id").param("id", original.getId()).query().singleRow();
		for (String column : List.of("attributes", "state", "authorization_code_value", "authorization_code_metadata", "access_token_value", "access_token_metadata", "oidc_id_token_value", "oidc_id_token_metadata", "refresh_token_value", "refresh_token_metadata")) {
			assertThat(raw.get(column).toString()).startsWith("enc:v1:").doesNotContain("private-", "token-", "https://issuer.example");
		}
		assertThat(this.authorizations.findByToken("unknown", null)).isEmpty();
		assertThat(this.authorizations.findByToken("", null)).isEmpty();
		assertThat(this.authorizations.findByToken("x".repeat(16_385), null)).isEmpty();
		assertThat(this.authorizations.findByToken("\ud800", null)).isEmpty();
		assertThat(this.authorizations.findByToken(original.getAccessToken().getToken().getTokenValue(), "code")).isEmpty();
		assertThat(this.authorizations.findByToken(original.getAccessToken().getToken().getTokenValue(), "unsupported")).isEmpty();
	}

	@Test
	void anAuthorizationCanAcquireAndRemoveTokensWithoutInventingAbsentFields() {
		var source = OAuth2Authorization.withRegisteredClient(this.client).id(UUID.randomUUID().toString()).principalName(this.userId.toString())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();
		var first = this.authorizations.save(source, 0);
		assertThat(first.authorization()).isEqualTo(source);
		Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
		var code = new OAuth2AuthorizationCode("code-token-new", now, now.plusSeconds(60));
		var second = this.authorizations.save(OAuth2Authorization.from(source).authorizedScopes(Set.of("openid")).token(code).build(), 1);
		assertThat(this.authorizations.findByToken(code.getTokenValue(), "code")).contains(second);
		var third = this.authorizations.save(source, 2);
		assertThat(third.authorization()).isEqualTo(source);
		assertThat(this.authorizations.findByToken(code.getTokenValue(), "code")).isEmpty();
	}

	@Test
	void updateReplacesLookupIndexesAndRejectsStaleVersionsOrDifferentSubjects() {
		var first = this.authorizations.save(authorization(), 0);
		var previous = first.authorization().getRefreshToken().getToken();
		var next = OAuth2Authorization.from(first.authorization()).token(new OAuth2RefreshToken("refresh-token-new", previous.getIssuedAt(), previous.getExpiresAt())).build();
		var second = this.authorizations.save(next, 1);
		assertThat(second.version()).isEqualTo(2);
		assertThat(this.authorizations.findByToken(previous.getTokenValue(), "refresh_token")).isEmpty();
		assertThat(this.authorizations.findByToken("refresh-token-new", "refresh_token")).contains(second);
		assertThatThrownBy(() -> this.authorizations.save(next, 1)).isInstanceOf(OptimisticLockingFailureException.class);
		UUID other = this.users.create("bobby", "Bob", SYSTEM).id();
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(next).principalName(other.toString()).build(), 2)).isInstanceOf(IllegalArgumentException.class);
		assertThat(this.authorizations.findById(UUID.fromString(next.getId()))).contains(second);
		assertThatThrownBy(() -> this.authorizations.remove(UUID.fromString(next.getId()), 1)).isInstanceOf(OptimisticLockingFailureException.class);
		this.authorizations.remove(UUID.fromString(next.getId()), 2);
		for (String table : TABLES) { assertThat(this.jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single()).isZero(); }
	}

	@Test
	void completeProtocolStateReloadsInANewApplicationAndAcrossDatabaseTimeZones() {
		var saved = this.authorizations.save(authorization(), 0);
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> {
			this.jdbc.sql("SET LOCAL TIME ZONE 'Pacific/Auckland'").update();
			assertThat(this.authorizations.findById(UUID.fromString(saved.authorization().getId()))).contains(saved);
		});
		try (var restarted = new SpringApplicationBuilder(IamApplication.class).web(WebApplicationType.NONE).properties(Map.of(
				"spring.datasource.url", this.postgres.getJdbcUrl(), "spring.datasource.username", this.postgres.getUsername(), "spring.datasource.password", this.postgres.getPassword(),
				"iam.authorization.key-file", KEY_FILE.toString(), "spring.main.banner-mode", "off")).run()) {
			assertThat(restarted.getBean(IdentityAuthorizations.class).findById(UUID.fromString(saved.authorization().getId()))).contains(saved);
		}
	}

	@Test
	void frameworkTimestampPrecisionIsVerifiedWithoutChangingSerializedClaims() {
		var original = authorization();
		Instant now = Instant.parse("2026-10-20T11:23:45.123456789Z");
		var changed = OAuth2Authorization.from(original).token(new OAuth2AuthorizationCode("code-precision", now, now.plusSeconds(60))).build();
		var saved = this.authorizations.save(changed, 0).authorization();
		assertThat(saved.getToken(OAuth2AuthorizationCode.class).getToken().getIssuedAt()).isEqualTo(Instant.parse("2026-10-20T11:23:45.123457Z"));
		assertThat(saved.getToken(OidcIdToken.class).getToken().getClaims()).isEqualTo(original.getToken(OidcIdToken.class).getToken().getClaims());
	}

	@Test
	void serializedAuthenticationAndClaimsKeepNanosecondTimesThroughOfficialSecurityDeserializers() {
		Instant time = Instant.parse("2026-10-20T11:23:45.123456789Z");
		var factor = FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY).issuedAt(time).build();
		var principal = UsernamePasswordAuthenticationToken.authenticated(this.userId.toString(), null, List.of(factor));
		Map<String, Object> claims = Map.of("iss", "https://issuer.example", "sub", this.userId.toString(), "aud", List.of(this.client.getClientId()), "iat", time, "exp", time.plusSeconds(300));
		var source = OAuth2Authorization.from(authorization()).attribute(Principal.class.getName(), principal).attribute("exact-time", time)
				.token(new OidcIdToken("id-token-precise", time, time.plusSeconds(300), claims), metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims)).build();
		var stored = this.authorizations.save(source, 0).authorization();
		assertThat(stored.<Object>getAttribute(Principal.class.getName())).isEqualTo(principal);
		assertThat(stored.<Instant>getAttribute("exact-time")).isEqualTo(time);
		assertThat(stored.getToken(OidcIdToken.class).getToken().getClaims()).isEqualTo(claims);
	}

	@Test
	void concurrentChangesOfOneSnapshotHaveOneWinner() throws Exception {
		var original = this.authorizations.save(authorization(), 0);
		var start = new CountDownLatch(1);
		try (var executor = Executors.newFixedThreadPool(2)) {
			var attempts = List.of("first", "second").stream().map(value -> executor.submit(() -> {
				assertThat(start.await(10, TimeUnit.SECONDS)).isTrue();
				try { this.authorizations.save(OAuth2Authorization.from(original.authorization()).attribute("revision-test", value).build(), 1); return true; }
				catch (OptimisticLockingFailureException ex) { return false; }
			})).toList();
			start.countDown();
			assertThat(List.of(attempts.get(0).get(10, TimeUnit.SECONDS), attempts.get(1).get(10, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
		}
		assertThat(this.authorizations.findById(UUID.fromString(original.authorization().getId())).orElseThrow().version()).isEqualTo(2);
	}

	@Test
	void aWriterWaitingForTheRecordLockReadsTheNewVersionAndIndexesInAFreshStatement() throws Exception {
		var saved = this.authorizations.save(authorization(), 0);
		try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword());
				var executor = Executors.newSingleThreadExecutor()) {
			connection.setAutoCommit(false);
			try (var update = connection.prepareStatement("UPDATE iam_authorization_record SET version=version+1 WHERE id=?")) { update.setString(1, saved.authorization().getId()); update.executeUpdate(); }
			var write = executor.submit(() -> {
				try { this.authorizations.save(OAuth2Authorization.from(saved.authorization()).attribute("change", "queued").build(), 1); return false; }
				catch (OptimisticLockingFailureException ex) { return true; }
			});
			try { await().atMost(Duration.ofSeconds(5)).until(() -> this.jdbc.sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%FOR UPDATE OF a,r%'").query(Long.class).single() > 0); }
			finally { connection.commit(); }
			assertThat(write.get(10, TimeUnit.SECONDS)).isTrue();
		}
	}

	@ParameterizedTest
	@ValueSource(strings = { "create-native-suppressed", "update-native-suppressed", "update-native-altered", "create-record-suppressed", "update-record-suppressed", "create-index-suppressed", "update-index-suppressed", "create-index-altered", "update-index-altered", "create-commit", "update-commit" })
	void suppressedAlteredAndDeferredWritesCannotPartlyApplyProtectedState(String fault) {
		boolean update = fault.startsWith("update");
		var source = update ? this.authorizations.save(authorization(), 0).authorization() : authorization();
		var before = snapshot();
		String table = fault.contains("native") ? "oauth2_authorization" : fault.contains("index") ? "iam_authorization_token_index" : "iam_authorization_record";
		String effect = fault.endsWith("suppressed") ? "RETURN NULL;" : fault.endsWith("altered")
				? table.equals("oauth2_authorization") ? "NEW.attributes=NEW.authorization_code_metadata;" : "NEW.digest=repeat('0',64);"
				: "RAISE EXCEPTION 'test deferred authorization failure';";
		this.jdbc.sql("CREATE FUNCTION authorization_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + effect + " RETURN NEW; END $$").update();
		boolean deferred = fault.endsWith("commit");
		String event = update && !table.equals("iam_authorization_token_index") ? "UPDATE" : "INSERT";
		this.jdbc.sql((deferred ? "CREATE CONSTRAINT TRIGGER" : "CREATE TRIGGER") + " authorization_test_fault " + (deferred ? "AFTER " : "BEFORE ") + event + " ON " + table
				+ (deferred ? " DEFERRABLE INITIALLY DEFERRED" : "") + " FOR EACH ROW EXECUTE FUNCTION authorization_test_fault()").update();
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).attribute("mutation", "private-mutation").build(), update ? 1 : 0)).isInstanceOf(RuntimeException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void outerRollbackAndSuppressedRemovalPreserveAtomicity() {
		var source = authorization();
		new TransactionTemplate(this.transactions).executeWithoutResult(tx -> { this.authorizations.save(source, 0); tx.setRollbackOnly(); });
		assertThat(this.authorizations.findById(UUID.fromString(source.getId()))).isEmpty();
		this.authorizations.save(source, 0);
		var before = snapshot();
		this.jdbc.sql("CREATE FUNCTION authorization_test_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$").update();
		this.jdbc.sql("CREATE TRIGGER authorization_test_fault BEFORE DELETE ON oauth2_authorization FOR EACH ROW EXECUTE FUNCTION authorization_test_fault()").update();
		assertThatThrownBy(() -> this.authorizations.remove(UUID.fromString(source.getId()), 1)).isInstanceOf(IllegalStateException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@ParameterizedTest
	@ValueSource(strings = { "row", "column", "ciphertext", "index", "scope", "expiry", "subject" })
	void ciphertextSwapsAlterationsAndIndexDriftFailClosed(String tamper) {
		var first = this.authorizations.save(authorization(), 0);
		switch (tamper) {
			case "row" -> {
				var second = this.authorizations.save(authorization(), 0);
				this.jdbc.sql("UPDATE oauth2_authorization SET attributes=(SELECT attributes FROM oauth2_authorization WHERE id=:other) WHERE id=:id").param("other", second.authorization().getId()).param("id", first.authorization().getId()).update();
			}
			case "column" -> this.jdbc.sql("UPDATE oauth2_authorization SET attributes=authorization_code_metadata WHERE id=:id").param("id", first.authorization().getId()).update();
			case "ciphertext" -> this.jdbc.sql("UPDATE oauth2_authorization SET attributes=attributes || 'AA' WHERE id=:id").param("id", first.authorization().getId()).update();
			case "scope" -> this.jdbc.sql("UPDATE oauth2_authorization SET authorized_scopes='openid' WHERE id=:id").param("id", first.authorization().getId()).update();
			case "expiry" -> this.jdbc.sql("UPDATE oauth2_authorization SET access_token_expires_at=access_token_expires_at + interval '1 day' WHERE id=:id").param("id", first.authorization().getId()).update();
			case "subject" -> {
				this.jdbc.sql("ALTER TABLE oauth2_authorization DISABLE TRIGGER iam_authorization_identity_protection").update();
				try { this.jdbc.sql("UPDATE oauth2_authorization SET principal_name=:other WHERE id=:id").param("other", UUID.randomUUID().toString()).param("id", first.authorization().getId()).update(); }
				finally { this.jdbc.sql("ALTER TABLE oauth2_authorization ENABLE TRIGGER iam_authorization_identity_protection").update(); }
			}
			default -> this.jdbc.sql("UPDATE iam_authorization_token_index SET digest=repeat('0',64) WHERE authorization_id=:id AND token_type='code'").param("id", first.authorization().getId()).update();
		}
		assertThatThrownBy(() -> this.authorizations.findById(UUID.fromString(first.authorization().getId()))).isInstanceOf(IllegalStateException.class)
				.hasMessageNotContaining("private-").hasMessageNotContaining("code-token-").hasMessageNotContaining("access-token-");
	}

	@ParameterizedTest
	@ValueSource(strings = { "state", "authorization_code_metadata", "access_token_metadata", "oidc_id_token_metadata", "refresh_token_metadata" })
	void removingProtectedFieldsCannotRestoreInvalidatedTokenDefaults(String column) {
		var source = invalidated(authorization());
		var saved = this.authorizations.save(source, 0);
		assertThat(saved.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(saved.authorization().getAccessToken().isInvalidated()).isTrue();
		assertThat(saved.authorization().getRefreshToken().isInvalidated()).isTrue();
		this.jdbc.sql("UPDATE oauth2_authorization SET " + column + "=NULL WHERE id=:id").param("id", source.getId()).update();
		assertThatThrownBy(() -> this.authorizations.findById(UUID.fromString(source.getId()))).isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> this.authorizations.findByToken(source.getAccessToken().getToken().getTokenValue(), "access_token")).isInstanceOf(IllegalStateException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "authorization_code", "access_token", "oidc_id_token", "refresh_token" })
	void removingAnEntireTokenAndItsIndexStillInvalidatesTheRecord(String prefix) {
		var source = authorization();
		this.authorizations.save(source, 0);
		String columns = prefix + "_value=NULL," + prefix + "_issued_at=NULL," + prefix + "_expires_at=NULL," + prefix + "_metadata=NULL";
		if (prefix.equals("access_token")) { columns += ",access_token_type=NULL,access_token_scopes=NULL"; }
		this.jdbc.sql("UPDATE oauth2_authorization SET " + columns + " WHERE id=:id").param("id", source.getId()).update();
		String type = prefix.equals("authorization_code") ? "code" : prefix.equals("oidc_id_token") ? "id_token" : prefix;
		this.jdbc.sql("DELETE FROM iam_authorization_token_index WHERE authorization_id=:id AND token_type=:type").param("id", source.getId()).param("type", type).update();
		assertThatThrownBy(() -> this.authorizations.findById(UUID.fromString(source.getId()))).isInstanceOf(IllegalStateException.class);
	}

	@ParameterizedTest
	@ValueSource(strings = { "attributes", "authorization_code_metadata", "access_token_metadata", "oidc_id_token_metadata", "refresh_token_metadata" })
	void ciphertextFromAnEarlierWriteCannotReplaceCurrentInvalidationMetadata(String column) {
		var first = this.authorizations.save(authorization(), 0);
		String old = this.jdbc.sql("SELECT " + column + " FROM oauth2_authorization WHERE id=:id").param("id", first.authorization().getId()).query(String.class).single();
		var second = this.authorizations.save(invalidated(first.authorization()), 1);
		assertThat(second.authorization().getToken(OAuth2AuthorizationCode.class).isInvalidated()).isTrue();
		assertThat(second.authorization().getAccessToken().isInvalidated()).isTrue();
		assertThat(second.authorization().getRefreshToken().isInvalidated()).isTrue();
		this.jdbc.sql("UPDATE oauth2_authorization SET " + column + "=:old WHERE id=:id").param("old", old).param("id", first.authorization().getId()).update();
		assertThatThrownBy(() -> this.authorizations.findById(UUID.fromString(first.authorization().getId()))).isInstanceOf(IllegalStateException.class);
	}

	@Test
	void databaseConstraintsRejectPlaintextAndReusedTokensWithoutChangingAnotherGrant() {
		var source = authorization();
		var saved = this.authorizations.save(source, 0);
		var before = snapshot();
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE oauth2_authorization SET authorization_code_value='plaintext-secret' WHERE id=:id").param("id", source.getId()).update()).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.jdbc.sql("UPDATE oauth2_authorization SET attributes=NULL WHERE id=:id").param("id", source.getId()).update()).isInstanceOf(DataIntegrityViolationException.class);
		var collision = OAuth2Authorization.from(source).id(UUID.randomUUID().toString()).build();
		assertThatThrownBy(() -> this.authorizations.save(collision, 0)).isInstanceOf(DataIntegrityViolationException.class);
		assertThat(snapshot()).isEqualTo(before);
		assertThat(this.authorizations.findById(UUID.fromString(source.getId()))).contains(saved);
	}

	@Test
	void officialSchemaColumnOrderAndPostgresqlTextContractRemainCompatible() throws Exception {
		String schema = new ClassPathResource("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql").getContentAsString(StandardCharsets.UTF_8);
		var names = Pattern.compile("(?m)^    ([a-z_]+) (?:varchar|blob|timestamp)").matcher(schema).results().map(result -> result.group(1)).toList();
		assertThat(names).hasSize(33);
		assertThat(this.jdbc.sql("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='oauth2_authorization' ORDER BY ordinal_position").query(String.class).list()).isEqualTo(names);
		var textColumns = this.jdbc.sql("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='oauth2_authorization' AND data_type='text'").query(String.class).list();
		assertThat(textColumns).contains("attributes", "state", "authorization_code_value", "access_token_metadata", "oidc_id_token_value", "refresh_token_metadata");
	}

	@Test
	void unknownPolymorphicPayloadTypesAreRejectedWithoutLeakingOrStoringTheirValues() {
		var before = snapshot();
		var source = OAuth2Authorization.from(authorization()).attribute("custom", new UnsupportedPayload("private-custom-secret")).build();
		assertThatThrownBy(() -> this.authorizations.save(source, 0)).isInstanceOf(IllegalStateException.class).hasMessageNotContaining("private-custom-secret").hasNoCause();
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void oversizedAttributesAndIncorrectSubjectsNeverProducePartialRecords() {
		var source = authorization();
		var before = snapshot();
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).attribute("large", "x".repeat(65_536)).build(), 0)).isInstanceOf(IllegalArgumentException.class);
		var code = source.getToken(OAuth2AuthorizationCode.class).getToken();
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).token(new OAuth2AuthorizationCode("\ud800", code.getIssuedAt(), code.getExpiresAt())).build(), 0)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).principalName(UUID.randomUUID().toString()).build(), 0)).isInstanceOf(DataIntegrityViolationException.class);
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).id("1-1-1-1-1").build(), 0)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> this.authorizations.save(OAuth2Authorization.from(source).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build(), 0)).isInstanceOf(IllegalArgumentException.class);
		assertThat(snapshot()).isEqualTo(before);
	}

	@Test
	void ambiguousStateLookupCannotSelectAnUnrelatedAuthorization() {
		var first = this.authorizations.save(authorization(), 0);
		var other = OAuth2Authorization.from(authorization()).attribute(OAuth2ParameterNames.STATE, first.authorization().getAttribute(OAuth2ParameterNames.STATE)).build();
		var second = this.authorizations.save(other, 0);
		assertThatThrownBy(() -> this.authorizations.findByToken(first.authorization().getAttribute(OAuth2ParameterNames.STATE), "state")).isInstanceOf(IllegalStateException.class);
		assertThat(this.authorizations.findByToken(second.authorization().getAccessToken().getToken().getTokenValue(), null)).contains(second);
	}

	@Test
	void upgradingV25KeepsClientsAndPriorIdentitiesAndAddsOnlyEmptyProtocolTables() throws Exception {
		String schema = "authorization_upgrade_" + UUID.randomUUID().toString().replace("-", "");
		this.jdbc.sql("CREATE SCHEMA " + schema).update();
		try {
			Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("25").load().migrate();
			try (var connection = DriverManager.getConnection(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword())) {
				connection.setSchema(schema); var old = JdbcClient.create(new SingleConnectionDataSource(connection, true));
				copyRows(old, "iam_user"); copyRows(old, "iam_resource"); copyRows(old, "iam_resource_role");
				old.sql("INSERT INTO oauth2_registered_client SELECT * FROM public.oauth2_registered_client").update();
				copyRows(old, "iam_client"); copyRows(old, "iam_client_allowed_role"); copyRows(old, "iam_security_audit");
				var tables = List.of("iam_user", "iam_resource", "iam_resource_role", "oauth2_registered_client", "iam_client", "iam_client_allowed_role", "iam_security_audit");
				var before = tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList();
				var migration = Flyway.configure().dataSource(this.postgres.getJdbcUrl(), this.postgres.getUsername(), this.postgres.getPassword()).schemas(schema).defaultSchema(schema).target("26").load();
				assertThat(migration.migrate().migrationsExecuted).isEqualTo(1);
				assertThat(tables.stream().map(table -> old.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList()).isEqualTo(before);
				for (String table : TABLES) { assertThat(old.sql("SELECT count(*) FROM " + table).query(Long.class).single()).isZero(); }
				assertThat(migration.migrate().migrationsExecuted).isZero();
			}
		}
		finally { this.jdbc.sql("DROP SCHEMA " + schema + " CASCADE").update(); }
	}

	private OAuth2Authorization authorization() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
		String suffix = UUID.randomUUID().toString();
		Map<String, Object> claims = Map.of("iss", "https://issuer.example", "sub", this.userId.toString(), "aud", List.of(this.client.getClientId()), "iat", now, "exp", now.plusSeconds(300), "nonce", "private-nonce-" + suffix);
		var principal = UsernamePasswordAuthenticationToken.authenticated(this.userId.toString(), null, List.of(new SimpleGrantedAuthority("FACTOR_PASSWORD")));
		var request = OAuth2AuthorizationRequest.authorizationCode().authorizationUri("https://issuer.example/oauth2/authorize").clientId(this.client.getClientId())
				.redirectUri("https://orders.example/callback").scopes(Set.of("openid", "profile", "offline_access")).state("private-client-state-" + suffix)
				.additionalParameters(Map.of("code_challenge", "private-challenge-" + suffix, "code_challenge_method", "S256")).build();
		return OAuth2Authorization.withRegisteredClient(this.client).id(UUID.randomUUID().toString()).principalName(this.userId.toString()).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizedScopes(Set.of("openid", "profile", "offline_access")).attribute(Principal.class.getName(), principal).attribute(OAuth2AuthorizationRequest.class.getName(), request)
				.attribute(OAuth2ParameterNames.STATE, "private-state-" + suffix).attribute("private-attribute", "private-attribute-value")
				.token(new OAuth2AuthorizationCode("code-token-" + suffix, now, now.plusSeconds(60)), metadata -> metadata.put("private-metadata", "private-code-metadata"))
				.token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token-" + suffix, now, now.plusSeconds(300), Set.of("openid", "profile", "offline_access")), metadata -> metadata.put("private-metadata", "private-access-metadata"))
				.token(new OidcIdToken("id-token-" + suffix, now, now.plusSeconds(300), claims), metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims))
				.token(new OAuth2RefreshToken("refresh-token-" + suffix, now, now.plusSeconds(604800)), metadata -> metadata.put("private-metadata", "private-refresh-metadata")).build();
	}
	private static OAuth2Authorization invalidated(OAuth2Authorization source) {
		var builder = OAuth2Authorization.from(source);
		for (var type : List.of(OAuth2AuthorizationCode.class, OAuth2AccessToken.class, OidcIdToken.class, OAuth2RefreshToken.class)) {
			builder.token(source.getToken(type).getToken(), metadata -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
		}
		return builder.build();
	}
	private List<List<String>> snapshot() { return TABLES.stream().map(table -> this.jdbc.sql("SELECT to_jsonb(r)::text FROM " + table + " r ORDER BY 1").query(String.class).list()).toList(); }
	private record UnsupportedPayload(String secret) { }
	private static Path keyFile() {
		try { Path file = Files.createTempFile("iam-authorization-test-", ".key"); byte[] bytes = new byte[64]; new SecureRandom().nextBytes(bytes); Files.write(file, bytes); file.toFile().deleteOnExit(); return file; }
		catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
	}

}
