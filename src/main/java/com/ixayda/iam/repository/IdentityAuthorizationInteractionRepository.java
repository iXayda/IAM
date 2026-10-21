package com.ixayda.iam.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationInteraction;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;

import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Immutable encrypted requests; only digests and authenticated timing bounds remain queryable. */
@Repository
@RegisterReflectionForBinding(IdentityAuthorizationInteraction.Request.class)
public class IdentityAuthorizationInteractionRepository {

	private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
			.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
	private final JdbcClient jdbc;
	private final AuthorizationSecrets secrets;

	IdentityAuthorizationInteractionRepository(JdbcClient jdbc, AuthorizationSecrets secrets) { this.jdbc = jdbc; this.secrets = secrets; }

	/** Admission owns only this owner lock and pending rows; it must not acquire identity or catalog locks. */
	public void lockOwner(String owner) {
		this.jdbc.sql("SELECT pg_advisory_xact_lock(hashtextextended(:owner,739121))").param("owner", owner).query().singleRow();
	}

	public long countPending(String owner) {
		return this.jdbc.sql("SELECT count(*) FROM iam_authorization_interaction WHERE owner_digest=:owner AND clock_timestamp() < expires_at")
				.param("owner", owner).query(Long.class).single();
	}

	public Instant now() { return this.jdbc.sql("SELECT clock_timestamp()").query(OffsetDateTime.class).single().toInstant(); }

	public boolean isWritableReadCommittedTransaction() {
		return this.jdbc.sql("SELECT current_setting('transaction_isolation')='read committed' AND current_setting('transaction_read_only')='off'").query(Boolean.class).single();
	}

	public Optional<StoredInteraction> findByDigest(String handle, String owner) {
		return this.jdbc.sql("SELECT * FROM iam_authorization_interaction WHERE handle_digest=:handle AND owner_digest=:owner")
				.param("handle", handle).param("owner", owner).query((row, index) -> read(row)).optional();
	}

	/** After waiting, use a new statement snapshot and authenticate all immutable fields again. */
	public Optional<StoredInteraction> lockByDigest(String handle, String owner) {
		var id = this.jdbc.sql("SELECT id FROM iam_authorization_interaction WHERE handle_digest=:handle AND owner_digest=:owner FOR UPDATE")
				.param("handle", handle).param("owner", owner).query(UUID.class).optional();
		return id.flatMap(ignored -> findByDigest(handle, owner));
	}

	public void insert(StoredInteraction stored) {
		var interaction = stored.interaction();
		String plaintext;
		try { plaintext = JSON.writeValueAsString(interaction.request()); }
		catch (RuntimeException ex) { throw invalid(); }
		String ciphertext = this.secrets.encrypt(interaction.id(), "interaction_request", binding(stored), plaintext);
		requireOne(this.jdbc.sql("""
				INSERT INTO iam_authorization_interaction(id,handle_digest,owner_digest,original_authenticated_at,created_at,expires_at,request)
				VALUES (:id,:handle,:owner,:authenticated,:created,:expiry,:request)
				""").param("id", interaction.id()).param("handle", stored.handleDigest()).param("owner", stored.ownerDigest())
				.param("authenticated", interaction.originalAuthenticatedAt()).param("created", timestamp(interaction.createdAt()))
				.param("expiry", timestamp(interaction.expiresAt())).param("request", ciphertext).update());
		if (!findByDigest(stored.handleDigest(), stored.ownerDigest()).equals(Optional.of(stored))) { throw invalid(); }
	}

	public void delete(StoredInteraction stored) {
		requireOne(this.jdbc.sql("DELETE FROM iam_authorization_interaction WHERE id=:id AND handle_digest=:handle AND owner_digest=:owner")
				.param("id", stored.interaction().id()).param("handle", stored.handleDigest()).param("owner", stored.ownerDigest()).update());
		if (this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_authorization_interaction WHERE id=:id OR handle_digest=:handle)")
				.param("id", stored.interaction().id()).param("handle", stored.handleDigest()).query(Boolean.class).single()) { throw invalid(); }
	}

	/** Bounded cleanup never waits for an in-flight issuance and carries no authority transition. */
	public int deleteExpired(int maximum) {
		List<UUID> ids = this.jdbc.sql("""
				SELECT id FROM iam_authorization_interaction WHERE expires_at <= clock_timestamp()
				ORDER BY expires_at,id LIMIT :maximum FOR UPDATE SKIP LOCKED
				""").param("maximum", maximum).query(UUID.class).list();
		if (ids.isEmpty()) { return 0; }
		int removed = this.jdbc.sql("DELETE FROM iam_authorization_interaction WHERE id IN (:ids)").param("ids", ids).update();
		if (removed != ids.size() || this.jdbc.sql("SELECT EXISTS(SELECT 1 FROM iam_authorization_interaction WHERE id IN (:ids))")
				.param("ids", ids).query(Boolean.class).single()) { throw invalid(); }
		return removed;
	}

	private StoredInteraction read(ResultSet row) throws SQLException {
		try {
			UUID id = row.getObject("id", UUID.class);
			String handle = row.getString("handle_digest"), owner = row.getString("owner_digest");
			long authenticated = row.getLong("original_authenticated_at");
			Instant created = row.getObject("created_at", OffsetDateTime.class).toInstant(), expiry = row.getObject("expires_at", OffsetDateTime.class).toInstant();
			String value = this.secrets.decrypt(id, "interaction_request", binding(id, handle, owner, authenticated, created, expiry), row.getString("request"));
			var request = JSON.readValue(value, IdentityAuthorizationInteraction.Request.class);
			return new StoredInteraction(new IdentityAuthorizationInteraction(id, request, authenticated, created, expiry), handle, owner);
		}
		catch (RuntimeException ex) { throw invalid(); }
	}

	private String binding(StoredInteraction stored) {
		var value = stored.interaction();
		return binding(value.id(), stored.handleDigest(), stored.ownerDigest(), value.originalAuthenticatedAt(), value.createdAt(), value.expiresAt());
	}

	private String binding(UUID id, String handle, String owner, long authenticated, Instant created, Instant expiry) {
		return this.secrets.interactionBinding(id + "|" + handle + "|" + owner + "|" + authenticated + "|" + created + "|" + expiry);
	}

	private static OffsetDateTime timestamp(Instant value) { return value.atOffset(ZoneOffset.UTC); }
	private static IllegalStateException invalid() { return new IllegalStateException("Authorization interaction could not be authenticated or stored"); }
	private static void requireOne(int count) { if (count != 1) { throw invalid(); } }

	public record StoredInteraction(IdentityAuthorizationInteraction interaction, String handleDigest, String ownerDigest) {
		@Override public String toString() { return "StoredAuthorizationInteraction[REDACTED]"; }
	}

}
