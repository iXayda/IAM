package com.ixayda.iam.service;

import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import com.ixayda.iam.credential.AuthorizationSecrets;
import com.ixayda.iam.model.IdentityAuthorizationInteraction;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository;
import com.ixayda.iam.repository.IdentityAuthorizationInteractionRepository.StoredInteraction;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/** Browser binding and single use; the protocol workflow still owns authentication, client checks and audit. */
@Service
public class IdentityAuthorizationInteractions {

	private final IdentityAuthorizationInteractionRepository repository;
	private final AuthorizationSecrets secrets;

	IdentityAuthorizationInteractions(IdentityAuthorizationInteractionRepository repository, AuthorizationSecrets secrets) {
		this.repository = repository; this.secrets = secrets;
	}

	/** Keep this private random value in the server-side session, including legitimate login session-ID rotation. */
	public String newBrowserOwner() { return this.secrets.generateInteractionSecret(); }

	/** Only a fully validated original request may enter this workflow. No login or grant is created here. */
	@Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.READ_COMMITTED)
	public Ticket create(String owner, IdentityAuthorizationInteraction.Request request, long originalAuthenticatedAt) {
		Assert.isTrue(canonical(owner), "A generated browser owner is required"); Assert.notNull(request, "An authorization request is required");
		String digest = this.secrets.interactionOwnerDigest(owner);
		this.repository.lockOwner(digest);
		this.repository.deleteExpired(64);
		if (this.repository.countPending(digest) >= 8) { throw new InteractionLimitException(); }
		var now = this.repository.now().truncatedTo(ChronoUnit.MICROS);
		var interaction = new IdentityAuthorizationInteraction(UUID.randomUUID(), request, originalAuthenticatedAt, now, now.plusSeconds(600));
		String handle = this.secrets.generateInteractionSecret();
		this.repository.insert(new StoredInteraction(interaction, this.secrets.interactionDigest(handle), digest));
		if (!this.repository.now().isBefore(interaction.expiresAt())) { throw new ExpiredInteractionException(); }
		return new Ticket(handle, interaction);
	}

	/** A read grants no right to resume; the same browser, current security state and deadline must be rechecked. */
	public Optional<IdentityAuthorizationInteraction> find(String owner, String handle) {
		return lookup(owner, handle, false).map(StoredInteraction::interaction);
	}

	/** Acquire after signing, subject, catalog and source-browser locks, before creating native authorization state. */
	@Transactional(propagation = Propagation.MANDATORY)
	public Optional<IdentityAuthorizationInteraction> lockForUse(String owner, String handle) {
		requireTransaction();
		return lookup(owner, handle, true).map(StoredInteraction::interaction);
	}

	/** Consume inside the same transaction as code issuance and its verified mandatory success audit. */
	@Transactional(propagation = Propagation.MANDATORY)
	public void complete(String owner, String handle, IdentityAuthorizationInteraction expected) {
		Assert.notNull(expected, "An authorization interaction is required"); requireTransaction();
		var stored = lookup(owner, handle, true).filter(value -> value.interaction().equals(expected)).orElseThrow(ExpiredInteractionException::new);
		this.repository.delete(stored);
		if (!this.repository.now().isBefore(expected.expiresAt())) { throw new ExpiredInteractionException(); }
	}

	@Transactional(propagation = Propagation.REQUIRES_NEW, isolation = Isolation.READ_COMMITTED)
	public int purgeExpired(int maximum) {
		Assert.isTrue(maximum >= 1 && maximum <= 1000, "Cleanup batch must be between 1 and 1000");
		return this.repository.deleteExpired(maximum);
	}

	private Optional<StoredInteraction> lookup(String owner, String handle, boolean locked) {
		if (!canonical(owner) || !canonical(handle)) { return Optional.empty(); }
		String handleDigest = this.secrets.interactionDigest(handle), ownerDigest = this.secrets.interactionOwnerDigest(owner);
		var result = locked ? this.repository.lockByDigest(handleDigest, ownerDigest) : this.repository.findByDigest(handleDigest, ownerDigest);
		var now = this.repository.now();
		return result.filter(value -> !now.isBefore(value.interaction().createdAt()) && now.isBefore(value.interaction().expiresAt()));
	}

	private void requireTransaction() {
		if (!TransactionSynchronizationManager.isActualTransactionActive() || TransactionSynchronizationManager.isCurrentTransactionReadOnly()
				|| !this.repository.isWritableReadCommittedTransaction()) { throw new IllegalStateException("Authorization interactions require a writable read committed transaction"); }
	}

	private static boolean canonical(String value) {
		return value != null && value.matches("[A-Za-z0-9_-]{43}")
				&& Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(value)).equals(value);
	}

	public record Ticket(String handle, IdentityAuthorizationInteraction interaction) {
		@Override public String toString() { return "AuthorizationInteractionTicket[REDACTED]"; }
	}

	public static final class InteractionLimitException extends IllegalStateException {
		public InteractionLimitException() { super("Too many pending authorization interactions"); }
	}

	public static final class ExpiredInteractionException extends IllegalStateException {
		public ExpiredInteractionException() { super("Authorization interaction is unavailable"); }
	}

}
