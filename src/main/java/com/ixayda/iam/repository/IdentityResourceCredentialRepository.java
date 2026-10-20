package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResource;
import com.ixayda.iam.model.IdentityResourceCredential;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityResourceCredentialRepository {

	private final JdbcClient jdbc;

	IdentityResourceCredentialRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

	public Optional<StoredCredential> findByResourceId(UUID id) {
		return this.jdbc.sql("SELECT * FROM iam_resource_credential WHERE resource_id=:id")
				.param("id", id).query(IdentityResourceCredentialRepository::mapCredential).optional();
	}

	/** One statement prevents mixing resource and credential states from different snapshots. */
	public Optional<ActiveCredential> findActiveByResourceId(UUID id) {
		return this.jdbc.sql("""
				SELECT c.*, r.audience, r.display_name, r.version AS resource_version,
				    r.created_at AS resource_created_at, r.updated_at AS resource_updated_at
				FROM iam_resource_credential c JOIN iam_resource r ON r.id=c.resource_id
				WHERE r.id=:id AND r.status='active' AND c.status='active'
				""").param("id", id).query((row, index) -> new ActiveCredential(
						new IdentityResource(id, row.getString("audience"), row.getString("display_name"), IdentityResource.Status.ACTIVE,
								row.getLong("resource_version"), instant(row, "resource_created_at"), instant(row, "resource_updated_at")),
						mapCredential(row, index))).optional();
	}

	/** Caller holds the resource parent lock, including when no credential exists yet. */
	public IdentityResourceCredential create(UUID id, String hash) {
		Instant time = databaseTime();
		int changed = this.jdbc.sql("""
				INSERT INTO iam_resource_credential(resource_id,secret_hash,status,version,created_at,rotated_at,updated_at)
				VALUES (:id,:hash,'active',1,:time,:time,:time)
				""").param("id", id).param("hash", hash).param("time", OffsetDateTime.ofInstant(time, ZoneOffset.UTC)).update();
		var stored = findByResourceId(id).orElseThrow(() -> new IllegalStateException("Resource credential was not stored"));
		var value = stored.credential();
		if (changed != 1 || !hash.equals(stored.secretHash()) || value.status() != IdentityResourceCredential.Status.ACTIVE || value.version() != 1
				|| !time.equals(value.createdAt()) || !time.equals(value.rotatedAt()) || !time.equals(value.updatedAt())) {
			throw new IllegalStateException("Resource credential was not stored");
		}
		return value;
	}

	public IdentityResourceCredential update(StoredCredential previous, String hash, IdentityResourceCredential.Status status) {
		var old = previous.credential();
		long next = Math.addExact(old.version(), 1);
		boolean rotated = !hash.equals(previous.secretHash());
		Instant now = databaseTime();
		Instant time = now.isBefore(old.updatedAt()) ? old.updatedAt() : now;
		int changed = this.jdbc.sql("""
				UPDATE iam_resource_credential SET secret_hash=:hash,status=:status,version=:next,
				    updated_at=:time, rotated_at=CASE WHEN :rotated THEN :time ELSE rotated_at END
				WHERE resource_id=:id AND version=:version
				""")
				.param("hash", hash).param("status", status.name().toLowerCase(Locale.ROOT)).param("next", next).param("rotated", rotated)
				.param("time", OffsetDateTime.ofInstant(time, ZoneOffset.UTC))
				.param("id", old.resourceId()).param("version", old.version()).update();
		var stored = findByResourceId(old.resourceId()).orElseThrow(() -> new IllegalStateException("Resource credential was not stored"));
		var value = stored.credential();
		if (changed != 1 || !hash.equals(stored.secretHash()) || value.status() != status || value.version() != next
				|| !old.createdAt().equals(value.createdAt()) || !time.equals(value.updatedAt())
				|| (rotated ? !value.rotatedAt().equals(value.updatedAt()) : !value.rotatedAt().equals(old.rotatedAt()))) {
			throw new IllegalStateException("Resource credential was not stored");
		}
		return value;
	}

	public boolean isWritableReadCommittedTransaction() {
		return this.jdbc.sql("SELECT current_setting('transaction_isolation')='read committed' AND NOT current_setting('transaction_read_only')::boolean")
				.query(Boolean.class).single();
	}

	private Instant databaseTime() { return this.jdbc.sql("SELECT clock_timestamp()").query(OffsetDateTime.class).single().toInstant(); }

	private static StoredCredential mapCredential(ResultSet row, int index) throws SQLException {
		return new StoredCredential(new IdentityResourceCredential(row.getObject("resource_id", UUID.class),
				IdentityResourceCredential.Status.valueOf(row.getString("status").toUpperCase(Locale.ROOT)), row.getLong("version"),
				instant(row, "created_at"), instant(row, "rotated_at"), instant(row, "updated_at")), row.getString("secret_hash"));
	}

	private static Instant instant(ResultSet row, String column) throws SQLException { return row.getObject(column, OffsetDateTime.class).toInstant(); }

	public record StoredCredential(IdentityResourceCredential credential, String secretHash) {
		@Override
		public String toString() { return "StoredResourceCredential[REDACTED]"; }
	}

	public record ActiveCredential(IdentityResource resource, StoredCredential stored) {
		@Override
		public String toString() { return "ActiveResourceCredential[REDACTED]"; }
	}

}
