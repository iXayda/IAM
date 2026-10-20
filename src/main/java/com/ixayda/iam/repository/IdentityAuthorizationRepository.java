package com.ixayda.iam.repository;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.ixayda.iam.credential.AuthorizationSecrets;

import tools.jackson.databind.cfg.JsonNodeFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.stereotype.Repository;

/** Protects the official JDBC serialization at its column-mapping extension points. */
@Repository
@DependsOnDatabaseInitialization
public class IdentityAuthorizationRepository {

	// Official 7.1.1 parameter order; integration tests compare every column to the installed schema.
	private static final List<String> COLUMNS = List.of("id", "registered_client_id", "principal_name", "authorization_grant_type", "authorized_scopes",
			"attributes", "state", "authorization_code_value", "authorization_code_issued_at", "authorization_code_expires_at", "authorization_code_metadata",
			"access_token_value", "access_token_issued_at", "access_token_expires_at", "access_token_metadata", "access_token_type", "access_token_scopes",
			"oidc_id_token_value", "oidc_id_token_issued_at", "oidc_id_token_expires_at", "oidc_id_token_metadata",
			"refresh_token_value", "refresh_token_issued_at", "refresh_token_expires_at", "refresh_token_metadata",
			"user_code_value", "user_code_issued_at", "user_code_expires_at", "user_code_metadata", "device_code_value", "device_code_issued_at", "device_code_expires_at", "device_code_metadata");
	private static final String SELECT = """
			SELECT a.*,r.version,r.user_id AS record_user_id,r.client_id AS record_client_id,
			    ARRAY(SELECT i.token_type || ':' || i.digest FROM iam_authorization_token_index i WHERE i.authorization_id=a.id ORDER BY i.token_type) AS token_indexes
			FROM oauth2_authorization a JOIN iam_authorization_record r ON r.id=a.id
			""";
	private final JdbcClient jdbc;
	private final AuthorizationSecrets secrets;
	private final JdbcOAuth2AuthorizationService delegate;
	private final JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper parameters;
	private final JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper rows;

	IdentityAuthorizationRepository(JdbcClient jdbc, JdbcTemplate template, AuthorizationSecrets secrets) {
		this.jdbc = jdbc;
		this.secrets = secrets;
		var clients = new JdbcRegisteredClientRepository(template);
		this.delegate = new JdbcOAuth2AuthorizationService(template, clients);
		var validator = BasicPolymorphicTypeValidator.builder();
		// Java 21 immutable collection implementations are concrete safe data containers, not a package-wide allowlist.
		Set.of(Map.of().getClass(), Map.of("key", "value").getClass(), List.of().getClass(), List.of("value").getClass(), Set.of().getClass(), Set.of("value").getClass())
				.forEach(validator::allowIfSubType);
		// Official security deserializers read trees; a double intermediary would change fractional-second Instants.
		var json = JsonMapper.builder().enable(JsonNodeFeature.USE_BIG_DECIMAL_FOR_FLOATS)
				.addModules(SecurityJacksonModules.getModules(getClass().getClassLoader(), validator)).build();
		this.parameters = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(json);
		this.rows = new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(clients, json);
		this.delegate.setAuthorizationParametersMapper(authorization -> {
			var plain = parameters(authorization);
			String binding = binding(plain);
			String attributes = this.secrets.encrypt(UUID.fromString(authorization.getId()), "attributes", binding, (String) plain.get(COLUMNS.indexOf("attributes")).getValue());
			String columnBinding = bindAttributes(binding, attributes);
			var protectedValues = new ArrayList<SqlParameterValue>(plain.size());
			for (int i = 0; i < plain.size(); i++) {
				var parameter = plain.get(i);
				String column = COLUMNS.get(i);
				Object value = parameter.getValue();
				if (column.equals("attributes")) { value = attributes; }
				else if (protectedColumn(column) && value != null) { value = this.secrets.encrypt(UUID.fromString(authorization.getId()), column, columnBinding, (String) value); }
				protectedValues.add(new SqlParameterValue(parameter.getSqlType(), value));
			}
			return protectedValues;
		});
		this.delegate.setAuthorizationRowMapper(this::authorization);
	}

	public Optional<StoredAuthorization> findById(UUID id) {
		return this.jdbc.sql(SELECT + " WHERE a.id=:id").param("id", id.toString()).query(this::snapshot).optional();
	}

	public Optional<StoredAuthorization> findByDigest(String digest, String type) {
		var found = this.jdbc.sql(SELECT + " WHERE EXISTS (SELECT 1 FROM iam_authorization_token_index i WHERE i.authorization_id=a.id AND i.digest=:digest AND (:type IS NULL OR i.token_type=:type))")
				.param("digest", digest).param("type", type, java.sql.Types.VARCHAR).query(this::snapshot).list();
		if (found.size() > 1) { throw new IllegalStateException("Protocol lookup is ambiguous"); }
		return found.stream().findFirst();
	}

	/** Serializes a missing id too; existing rows are locked before a fresh statement reads their index snapshot. */
	public Optional<StoredAuthorization> lockById(UUID id) {
		this.jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(:id,762941))").param("id", id.toString()).query().singleRow();
		this.jdbc.sql("SELECT a.id FROM oauth2_authorization a JOIN iam_authorization_record r ON r.id=a.id WHERE a.id=:id FOR UPDATE OF a,r")
				.param("id", id.toString()).query(String.class).optional();
		var found = findById(id);
		if (found.isEmpty() && this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM oauth2_authorization WHERE id=:id)").param("id", id.toString()).query(Boolean.class).single()) {
			throw new IllegalStateException("Protocol record is missing");
		}
		return found;
	}

	public StoredAuthorization save(OAuth2Authorization authorization, long previousVersion) {
		this.secrets.requireConfigured();
		var expected = parameters(authorization);
		var indexes = indexes(authorization);
		this.delegate.save(authorization);
		requireNativeValues(UUID.fromString(authorization.getId()), expected);
		long next = Math.addExact(previousVersion, 1);
		int changed = previousVersion == 0
				? this.jdbc.sql("INSERT INTO iam_authorization_record(id,user_id,client_id,version) VALUES (:id,:user,:client,:next)")
						.param("id", authorization.getId()).param("user", UUID.fromString(authorization.getPrincipalName())).param("client", authorization.getRegisteredClientId()).param("next", next).update()
				: this.jdbc.sql("UPDATE iam_authorization_record SET version=:next WHERE id=:id AND version=:previous")
						.param("next", next).param("id", authorization.getId()).param("previous", previousVersion).update();
		requireOne(changed);
		this.jdbc.sql("DELETE FROM iam_authorization_token_index WHERE authorization_id=:id").param("id", authorization.getId()).update();
		for (var index : indexes.entrySet()) {
			requireOne(this.jdbc.sql("INSERT INTO iam_authorization_token_index(authorization_id,token_type,digest) VALUES (:id,:type,:digest)")
					.param("id", authorization.getId()).param("type", index.getKey()).param("digest", index.getValue()).update());
		}
		var stored = findById(UUID.fromString(authorization.getId())).orElseThrow(() -> new IllegalStateException("Protocol record was not stored"));
		if (stored.version() != next) { throw new IllegalStateException("Protocol revision was not stored"); }
		return stored;
	}

	public void remove(StoredAuthorization current) {
		this.delegate.remove(current.authorization());
		if (this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM oauth2_authorization WHERE id=:id)").param("id", current.authorization().getId()).query(Boolean.class).single()
				|| this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_authorization_record WHERE id=:id)").param("id", current.authorization().getId()).query(Boolean.class).single()
				|| this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_authorization_token_index WHERE authorization_id=:id)").param("id", current.authorization().getId()).query(Boolean.class).single()) {
			throw new IllegalStateException("Protocol record was not removed");
		}
	}

	private StoredAuthorization snapshot(ResultSet row, int index) throws SQLException {
		var authorization = authorization(row, index);
		if (!authorization.getPrincipalName().equals(row.getObject("record_user_id", UUID.class).toString())
				|| !authorization.getRegisteredClientId().equals(row.getString("record_client_id"))) { throw new IllegalStateException("Protocol subjects do not match"); }
		var stored = Arrays.stream((Object[]) row.getArray("token_indexes").getArray()).map(Object::toString).sorted().toList();
		var expected = indexes(authorization).entrySet().stream().map(entry -> entry.getKey() + ":" + entry.getValue()).sorted().toList();
		if (!stored.equals(expected)) { throw new IllegalStateException("Protocol token indexes do not match"); }
		return new StoredAuthorization(authorization, row.getLong("version"));
	}

	private OAuth2Authorization authorization(ResultSet row, int index) throws SQLException {
		try { return this.rows.mapRow(decrypted(row), index); }
		catch (RuntimeException ex) { throw new IllegalStateException("Persisted protocol state could not be decoded"); }
	}

	/** Official PostgreSQL row mapping reads these TEXT fields through getString(String). */
	private ResultSet decrypted(ResultSet row) throws SQLException {
		UUID id = UUID.fromString(row.getString("id"));
		var rawValues = new ArrayList<Object>(COLUMNS.size());
		for (String column : COLUMNS) {
			rawValues.add(column.endsWith("_at") ? row.getTimestamp(column) : row.getString(column));
		}
		String binding = bindingValues(rawValues);
		String columnBinding = bindAttributes(binding, row.getString("attributes"));
		return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(), new Class<?>[] { ResultSet.class }, (proxy, method, arguments) -> {
			try {
				Object value = method.invoke(row, arguments);
				if (method.getName().equals("getString") && arguments.length == 1 && arguments[0] instanceof String column && protectedColumn(column) && value != null) {
					return this.secrets.decrypt(id, column, column.equals("attributes") ? binding : columnBinding, (String) value);
				}
				return value;
			}
			catch (InvocationTargetException ex) { throw ex.getCause(); }
		});
	}

	private static String binding(List<SqlParameterValue> parameters) { return bindingValues(parameters.stream().map(SqlParameterValue::getValue).toList()); }

	/** Authenticating presence prevents nullable metadata from restoring framework defaults. */
	private static String bindingValues(List<?> values) {
		try {
			var digest = MessageDigest.getInstance("SHA-256");
			for (int i = 0; i < COLUMNS.size(); i++) {
				Object value = values.get(i);
				digest.update((byte) (value == null ? 0 : 1));
				if (value != null && !protectedColumn(COLUMNS.get(i))) {
					String encoded = value instanceof Timestamp time ? round(time.toInstant()).toString() : value.toString();
					byte[] bytes = encoded.getBytes(StandardCharsets.UTF_8);
					digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array()); digest.update(bytes);
				}
			}
			return HexFormat.of().formatHex(digest.digest());
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("Protocol binding is unavailable"); }
	}

	/** Fresh encrypted attributes anchor every other protected column to the same write. */
	private static String bindAttributes(String binding, String attributes) {
		if (attributes == null) { throw new IllegalStateException("Protocol attributes are missing"); }
		try {
			var digest = MessageDigest.getInstance("SHA-256");
			digest.update(("iam:authorization-attributes:v1:" + binding + ":").getBytes(StandardCharsets.US_ASCII));
			return HexFormat.of().formatHex(digest.digest(attributes.getBytes(StandardCharsets.UTF_8)));
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("Protocol binding is unavailable"); }
	}

	private List<SqlParameterValue> parameters(OAuth2Authorization authorization) {
		List<SqlParameterValue> values;
		try { values = this.parameters.apply(authorization); }
		catch (RuntimeException ex) { throw new IllegalArgumentException("Protocol state could not be encoded"); }
		if (values.size() != COLUMNS.size()) { throw new IllegalStateException("Unsupported official protocol serialization"); }
		return values;
	}

	private Map<String, String> indexes(OAuth2Authorization authorization) {
		var result = new HashMap<String, String>();
		String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		if (state != null) { result.put("state", this.secrets.digest(state)); }
		for (var type : List.of(OAuth2AuthorizationCode.class, OAuth2AccessToken.class, OidcIdToken.class, OAuth2RefreshToken.class)) {
			var token = authorization.getToken(type);
			if (token != null) {
				String name = type == OAuth2AuthorizationCode.class ? "code" : type == OAuth2AccessToken.class ? "access_token" : type == OidcIdToken.class ? "id_token" : "refresh_token";
				result.put(name, this.secrets.digest(token.getToken().getTokenValue()));
			}
		}
		return result;
	}

	private void requireNativeValues(UUID id, List<SqlParameterValue> expected) {
		boolean matches = this.jdbc.sql("SELECT * FROM oauth2_authorization WHERE id=:id").param("id", id.toString()).query((row, n) -> {
			var decoded = decrypted(row);
			for (int i = 0; i < COLUMNS.size(); i++) {
				String column = COLUMNS.get(i);
				Object value = expected.get(i).getValue();
				if (value instanceof Timestamp time) {
					var stored = decoded.getTimestamp(column);
					if (stored == null || !round(time.toInstant()).equals(stored.toInstant())) { return false; }
				}
				else if (!java.util.Objects.equals(value, decoded.getString(column))) { return false; }
			}
			return true;
		}).optional().orElse(false);
		if (!matches) { throw new IllegalStateException("Protocol values were not stored"); }
	}

	private static Instant round(Instant time) { return Instant.ofEpochSecond(time.getEpochSecond(), ((time.getNano() + 500L) / 1000L) * 1000L); }
	private static boolean protectedColumn(String column) { return column.equals("attributes") || column.equals("state") || column.endsWith("_value") || column.endsWith("_metadata"); }
	private static void requireOne(int changed) { if (changed != 1) { throw new IllegalStateException("Protocol change was not stored"); } }

	public record StoredAuthorization(OAuth2Authorization authorization, long version) {
		@Override
		public String toString() { return "StoredAuthorization[version=" + version + ", REDACTED]"; }
	}

}
