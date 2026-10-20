package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentityRefreshHistory;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Native authorization locks precede family and history locks; all reads after waits use fresh statements. */
@Repository
public class IdentityRefreshTokenRepository {

	private final JdbcClient jdbc;
	private final AuthorizationSecrets secrets;

	IdentityRefreshTokenRepository(JdbcClient jdbc, AuthorizationSecrets secrets) { this.jdbc = jdbc; this.secrets = secrets; }

	public Optional<IdentityRefreshFamily> findFamily(UUID id) {
		return this.jdbc.sql("SELECT * FROM iam_refresh_family WHERE authorization_id=:id").param("id", id.toString()).query(IdentityRefreshTokenRepository::family).optional();
	}

	public Optional<IdentityRefreshFamily> lockFamily(UUID id) {
		this.jdbc.sql("SELECT authorization_id FROM iam_refresh_family WHERE authorization_id=:id FOR UPDATE").param("id", id.toString()).query(String.class).optional();
		return findFamily(id);
	}

	public void insertFamily(IdentityRefreshFamily family) {
		requireOne(parameters(this.jdbc.sql("""
				INSERT INTO iam_refresh_family(authorization_id,version,generation,current_digest,scopes,started_at,updated_at,idle_expires_at,absolute_expires_at,status)
				VALUES (:id,:version,:generation,:digest,:scopes,:started,:updated,:idle,:absolute,:status)
				"""), family).update());
		requireFamily(family);
	}

	public void updateFamily(IdentityRefreshFamily family, long previousVersion) {
		requireOne(parameters(this.jdbc.sql("""
				UPDATE iam_refresh_family SET version=:version,generation=:generation,current_digest=:digest,scopes=:scopes,started_at=:started,
				updated_at=:updated,idle_expires_at=:idle,absolute_expires_at=:absolute,status=:status
				WHERE authorization_id=:id AND version=:previous
				"""), family).param("previous", previousVersion).update());
		requireFamily(family);
	}

	public Optional<IdentityRefreshHistory> findHistory(String digest) {
		return this.jdbc.sql("SELECT * FROM iam_refresh_history WHERE digest=:digest").param("digest", digest).query(this::history).optional();
	}

	public Optional<IdentityRefreshHistory> lockHistory(String digest) {
		this.jdbc.sql("SELECT digest FROM iam_refresh_history WHERE digest=:digest FOR UPDATE").param("digest", digest).query(String.class).optional();
		return findHistory(digest);
	}

	public void consumeHistory(IdentityRefreshHistory history) {
		if (history.consumedAt() == null) { throw new IllegalArgumentException("Refresh consumption time is required"); }
		requireOne(this.jdbc.sql("""
				UPDATE iam_refresh_history SET consumed_at=:consumed,seal=:seal
				WHERE authorization_id=:id AND digest=:digest AND generation=:generation AND consumed_at IS NULL
				""").param("consumed", timestamp(history.consumedAt())).param("seal", this.secrets.refreshHistorySeal(encode(history)))
				.param("id", history.authorizationId().toString()).param("digest", history.digest()).param("generation", history.generation()).update());
		if (findHistory(history.digest()).filter(history::equals).isEmpty()) { throw new IllegalStateException("Refresh consumption was not stored"); }
	}

	public void insertHistory(IdentityRefreshHistory history) {
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_refresh_history(digest,authorization_id,generation,parent_digest,issued_at,expires_at,consumed_at,seal)
				VALUES (:digest,:id,:generation,:parent,:issued,:expires,:consumed,:seal)
				""").param("digest", history.digest()).param("id", history.authorizationId().toString()).param("generation", history.generation())
				.param("parent", history.parentDigest(), Types.VARCHAR).param("issued", timestamp(history.issuedAt())).param("expires", timestamp(history.expiresAt()))
				.param("consumed", timestamp(history.consumedAt()), Types.TIMESTAMP_WITH_TIMEZONE).param("seal", this.secrets.refreshHistorySeal(encode(history))).update());
		if (findHistory(history.digest()).filter(history::equals).isEmpty()) { throw new IllegalStateException("Refresh history was not stored"); }
	}

	private IdentityRefreshHistory history(ResultSet row, int index) throws SQLException {
		var result = new IdentityRefreshHistory(UUID.fromString(row.getString("authorization_id")), row.getString("digest"), row.getLong("generation"),
				row.getString("parent_digest"), row.getObject("issued_at", OffsetDateTime.class).toInstant(), row.getObject("expires_at", OffsetDateTime.class).toInstant(),
				row.getObject("consumed_at", OffsetDateTime.class) == null ? null : row.getObject("consumed_at", OffsetDateTime.class).toInstant());
		if (!this.secrets.verifiesRefreshHistory(encode(result), row.getString("seal"))) { throw new IllegalStateException("Refresh history does not match protected state"); }
		return result;
	}

	private void requireFamily(IdentityRefreshFamily expected) {
		if (findFamily(expected.authorizationId()).filter(expected::equals).isEmpty()) { throw new IllegalStateException("Refresh family was not stored"); }
	}

	private static IdentityRefreshFamily family(ResultSet row, int index) throws SQLException {
		return new IdentityRefreshFamily(UUID.fromString(row.getString("authorization_id")), row.getLong("version"), row.getLong("generation"), row.getString("current_digest"),
				Set.copyOf(Arrays.asList(row.getString("scopes").split(","))), row.getObject("started_at", OffsetDateTime.class).toInstant(), row.getObject("updated_at", OffsetDateTime.class).toInstant(),
				row.getObject("idle_expires_at", OffsetDateTime.class).toInstant(), row.getObject("absolute_expires_at", OffsetDateTime.class).toInstant(),
				IdentityRefreshFamily.Status.valueOf(row.getString("status").toUpperCase(Locale.ROOT)));
	}

	private static JdbcClient.StatementSpec parameters(JdbcClient.StatementSpec statement, IdentityRefreshFamily family) {
		return statement.param("id", family.authorizationId().toString()).param("version", family.version()).param("generation", family.generation()).param("digest", family.currentDigest())
				.param("scopes", String.join(",", new TreeSet<>(family.scopes()))).param("started", timestamp(family.startedAt())).param("updated", timestamp(family.updatedAt()))
				.param("idle", timestamp(family.idleExpiresAt())).param("absolute", timestamp(family.absoluteExpiresAt())).param("status", family.status().name().toLowerCase(Locale.ROOT));
	}

	private static String encode(IdentityRefreshHistory history) {
		return "iam:refresh-history:v1|" + history.authorizationId() + "|" + history.digest() + "|" + history.generation() + "|" + history.parentDigest()
				+ "|" + history.issuedAt() + "|" + history.expiresAt() + "|" + history.consumedAt();
	}

	private static OffsetDateTime timestamp(Instant value) { return value == null ? null : value.atOffset(ZoneOffset.UTC); }
	private static void requireOne(int count) { if (count != 1) { throw new IllegalStateException("Refresh state was not stored"); } }

}
