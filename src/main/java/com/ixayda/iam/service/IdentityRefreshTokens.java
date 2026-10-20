package com.ixayda.iam.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationBinding;
import com.ixayda.iam.model.IdentityRefreshFamily;
import com.ixayda.iam.model.IdentityRefreshHistory;
import com.ixayda.iam.repository.IdentityRefreshTokenRepository;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Trusted refresh persistence; the caller binds the authenticated client and owns the issuance or replay audit. */
@Service
public class IdentityRefreshTokens {

	private static final String FAMILY = "iam.refreshFamily";
	private final IdentityRefreshTokenRepository repository;
	private final IdentityAuthorizations authorizations;
	private final IdentityAuthorizationBindings bindings;
	private final AuthorizationSecrets secrets;

	IdentityRefreshTokens(IdentityRefreshTokenRepository repository, IdentityAuthorizations authorizations, IdentityAuthorizationBindings bindings, AuthorizationSecrets secrets) {
		this.repository = repository; this.authorizations = authorizations; this.bindings = bindings; this.secrets = secrets;
	}

	/** Resolves original history, including spent tokens; this lookup alone is never an active-grant decision. */
	public Optional<IdentityRefreshHistory> findByToken(String token) {
		String digest;
		try { digest = this.secrets.refreshDigest(token); }
		catch (IllegalArgumentException ex) { return Optional.empty(); }
		return this.repository.findHistory(digest);
	}

	/** The caller binds the authenticated client before locking this family or deciding replay. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<Context> lockForUse(IdentityAuthorizations.Snapshot previous, String token) {
		var id = java.util.UUID.fromString(previous.authorization().getId());
		var locked = this.authorizations.lockForUse(id).orElseThrow(() -> new IllegalStateException("Authorization is missing"));
		if (locked.version() != previous.version()) { throw new IllegalStateException("Authorization version is stale"); }
		var family = this.repository.lockFamily(id).map(value -> verify(locked.authorization(), value))
				.orElseThrow(() -> new IllegalStateException("Refresh family is missing"));
		return this.repository.lockHistory(this.secrets.refreshDigest(token)).filter(history -> history.authorizationId().equals(id))
				.map(history -> new Context(locked, family, history));
	}

	/** A single successor, its parent's spent seal and the protected family advance in the caller's audited transaction. */
	@Transactional(propagation = Propagation.MANDATORY)
	public IdentityAuthorizations.Snapshot rotate(Context previous, OAuth2Authorization authorization, OAuth2RefreshToken successor, Set<String> scopes) {
		var locked = this.authorizations.lockForUse(previous.family().authorizationId()).orElseThrow(() -> new IllegalStateException("Authorization is missing"));
		var current = this.repository.lockFamily(previous.family().authorizationId()).map(value -> verify(locked.authorization(), value)).orElseThrow();
		var parent = this.repository.lockHistory(previous.requested().digest()).orElseThrow();
		var original = this.bindings.findByAuthorization(locked.authorization()).orElseThrow();
		if (locked.version() != previous.authorization().version() || !current.equals(previous.family()) || !parent.equals(previous.requested())
				|| current.status() != IdentityRefreshFamily.Status.ACTIVE || parent.consumedAt() != null || !parent.digest().equals(current.currentDigest())
				|| this.bindings.findByAuthorization(authorization).filter(original::equals).isEmpty()
				|| !encode(current).equals(authorization.getAttribute(FAMILY)) || scopes.isEmpty() || !current.scopes().containsAll(scopes)
				|| successor.getIssuedAt().isBefore(current.updatedAt()) || !successor.getIssuedAt().isBefore(parent.expiresAt())
				|| successor.getExpiresAt().isAfter(current.absoluteExpiresAt()) || successor.getExpiresAt().isAfter(successor.getIssuedAt().plus(7, ChronoUnit.DAYS))
				|| authorization.getAccessToken() == null || !authorization.getAccessToken().isActive() || !authorization.getAccessToken().getToken().getScopes().equals(scopes)
				|| scopes.contains("offline_access") != (authorization.getRefreshToken() != null)
				|| authorization.getRefreshToken() != null && (!authorization.getRefreshToken().isActive() || !authorization.getRefreshToken().getToken().equals(successor))) {
			throw new IllegalStateException("Refresh successor is invalid");
		}
		String digest = this.secrets.refreshDigest(successor.getTokenValue());
		if (digest.equals(parent.digest())) { throw new IllegalStateException("Refresh successor repeats its parent"); }
		var next = new IdentityRefreshFamily(current.authorizationId(), Math.addExact(current.version(), 1), Math.addExact(current.generation(), 1), digest, scopes,
				current.startedAt(), successor.getIssuedAt(), successor.getExpiresAt(), current.absoluteExpiresAt(),
				scopes.contains("offline_access") ? IdentityRefreshFamily.Status.ACTIVE : IdentityRefreshFamily.Status.CLOSED);
		this.repository.consumeHistory(new IdentityRefreshHistory(parent.authorizationId(), parent.digest(), parent.generation(), parent.parentDigest(), parent.issuedAt(), parent.expiresAt(), successor.getIssuedAt()));
		this.repository.insertHistory(new IdentityRefreshHistory(current.authorizationId(), digest, next.generation(), parent.digest(), successor.getIssuedAt(), successor.getExpiresAt(), null));
		var saved = this.authorizations.save(OAuth2Authorization.from(authorization).attribute(FAMILY, encode(next)).build(), locked.version());
		this.repository.updateFamily(next, current.version());
		if (findByAuthorization(saved.authorization()).filter(next::equals).isEmpty()) { throw new IllegalStateException("Refresh successor was not stored"); }
		return saved;
	}

	public record Context(IdentityAuthorizations.Snapshot authorization, IdentityRefreshFamily family, IdentityRefreshHistory requested) { }

	/** The workflow already holds native authorization and all earlier locks; initial metadata is saved atomically with native tokens. */
	@Transactional(propagation = Propagation.MANDATORY)
	public IdentityAuthorizations.Snapshot initialize(OAuth2Authorization authorization, long expectedVersion, IdentityAuthorizationBinding binding) {
		var locked = this.authorizations.lockForUse(binding.id()).orElseThrow(() -> new IllegalStateException("Authorization is missing"));
		if (locked.version() != expectedVersion || authorization.getAttribute(FAMILY) != null || this.repository.lockFamily(binding.id()).isPresent()
				|| this.bindings.findByAuthorization(authorization).filter(binding::equals).isEmpty()) { throw new IllegalStateException("Initial refresh family is invalid"); }
		var refresh = authorization.getRefreshToken();
		if (refresh == null || !refresh.isActive() || !binding.scopes().contains("offline_access")) { throw new IllegalStateException("Initial refresh token is invalid"); }
		var token = refresh.getToken();
		var digest = this.secrets.refreshDigest(token.getTokenValue());
		var family = new IdentityRefreshFamily(binding.id(), 1, 0, digest, binding.scopes(), token.getIssuedAt(), token.getIssuedAt(),
				token.getExpiresAt(), binding.issuedAt().plus(30, ChronoUnit.DAYS), IdentityRefreshFamily.Status.ACTIVE);
		var history = new IdentityRefreshHistory(binding.id(), digest, 0, null, token.getIssuedAt(), token.getExpiresAt(), null);
		var saved = this.authorizations.save(OAuth2Authorization.from(authorization).attribute(FAMILY, encode(family)).build(), expectedVersion);
		this.repository.insertFamily(family); this.repository.insertHistory(history);
		if (findByAuthorization(saved.authorization()).filter(family::equals).isEmpty()) { throw new IllegalStateException("Refresh family was not stored"); }
		return saved;
	}

	/** Quarantine and native invalidation remain in the caller's committed denial transaction. */
	@Transactional(propagation = Propagation.MANDATORY)
	public IdentityAuthorizations.Snapshot quarantine(IdentityAuthorizations.Snapshot previous) {
		return terminate(previous, IdentityRefreshFamily.Status.QUARANTINED);
	}

	/** General revocation is terminal for every grant, including an unused code without a family. */
	@Transactional(propagation = Propagation.MANDATORY)
	public IdentityAuthorizations.Snapshot revoke(IdentityAuthorizations.Snapshot previous) {
		return terminate(previous, IdentityRefreshFamily.Status.REVOKED);
	}

	private IdentityAuthorizations.Snapshot terminate(IdentityAuthorizations.Snapshot previous, IdentityRefreshFamily.Status status) {
		var id = java.util.UUID.fromString(previous.authorization().getId());
		var locked = this.authorizations.lockForUse(id).orElseThrow(() -> new IllegalStateException("Authorization is missing"));
		if (locked.version() != previous.version()) { throw new IllegalStateException("Authorization version is stale"); }
		var found = this.repository.lockFamily(id);
		if (IdentityAuthorizations.isRevoked(locked.authorization())) {
			if (status != IdentityRefreshFamily.Status.REVOKED || findByAuthorization(locked.authorization()).filter(family -> family.status() != IdentityRefreshFamily.Status.REVOKED).isPresent()) {
				throw new IllegalStateException("Revoked authorization cannot change lifecycle state");
			}
			return locked;
		}
		var invalidated = status == IdentityRefreshFamily.Status.REVOKED ? IdentityAuthorizations.markRevoked(locked.authorization()) : IdentityAuthorizations.invalidate(locked.authorization());
		if (found.isEmpty()) {
			if (locked.authorization().getRefreshToken() != null || locked.authorization().getAttribute(FAMILY) != null) {
				throw new IllegalStateException("Refresh family is missing");
			}
			return this.authorizations.save(invalidated, previous.version());
		}
		var current = verify(locked.authorization(), found.orElseThrow());
		var now = Instant.now().truncatedTo(ChronoUnit.MICROS);
		if (now.isBefore(current.updatedAt())) { now = current.updatedAt(); }
		var next = new IdentityRefreshFamily(current.authorizationId(), Math.addExact(current.version(), 1), current.generation(), current.currentDigest(), current.scopes(),
				current.startedAt(), now, current.idleExpiresAt(), current.absoluteExpiresAt(), status);
		var saved = this.authorizations.save(OAuth2Authorization.from(invalidated).attribute(FAMILY, encode(next)).build(), previous.version());
		this.repository.updateFamily(next, current.version());
		if (findByAuthorization(saved.authorization()).filter(next::equals).isEmpty()) { throw new IllegalStateException("Terminal refresh state was not stored"); }
		return saved;
	}

	/** Original family metadata is authenticated by native storage; callers must separately check active epochs and deadlines. */
	public Optional<IdentityRefreshFamily> findByAuthorization(OAuth2Authorization authorization) {
		var family = this.repository.findFamily(java.util.UUID.fromString(authorization.getId()));
		if (family.isEmpty()) {
			if (authorization.getAttribute(FAMILY) != null || authorization.getRefreshToken() != null) { throw new IllegalStateException("Refresh family is missing"); }
			return Optional.empty();
		}
		return family.map(value -> verify(authorization, value));
	}

	private IdentityRefreshFamily verify(OAuth2Authorization authorization, IdentityRefreshFamily family) {
		if (!encode(family).equals(authorization.getAttribute(FAMILY))) { throw new IllegalStateException("Refresh family does not match protected state"); }
		var history = this.repository.findHistory(family.currentDigest()).orElseThrow(() -> new IllegalStateException("Current refresh history is missing"));
		if (!history.authorizationId().equals(family.authorizationId()) || history.generation() != family.generation()
				|| !history.expiresAt().equals(family.idleExpiresAt()) || history.issuedAt().isBefore(family.startedAt())) { throw new IllegalStateException("Current refresh history is invalid"); }
		if (family.status() == IdentityRefreshFamily.Status.ACTIVE) {
			var refresh = authorization.getRefreshToken();
			if (refresh == null || refresh.isInvalidated() || history.consumedAt() != null
					|| !this.secrets.refreshDigest(refresh.getToken().getTokenValue()).equals(family.currentDigest())
					|| !refresh.getToken().getIssuedAt().equals(history.issuedAt()) || !refresh.getToken().getExpiresAt().equals(history.expiresAt())) {
				throw new IllegalStateException("Current refresh token does not match protected state");
			}
		}
		return family;
	}

	private static String encode(IdentityRefreshFamily family) {
		return "iam:refresh-family:v1|" + family.authorizationId() + "|" + family.version() + "|" + family.generation() + "|" + family.currentDigest()
				+ "|" + String.join(",", new TreeSet<>(family.scopes())) + "|" + family.startedAt() + "|" + family.updatedAt() + "|" + family.idleExpiresAt()
				+ "|" + family.absoluteExpiresAt() + "|" + family.status();
	}

}
