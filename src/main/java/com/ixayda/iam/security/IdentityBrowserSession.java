package com.ixayda.iam.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.session.Session;
import org.springframework.util.SerializationUtils;

/** Tracks public Session mutations without inspecting the JDBC implementation's private delta. */
final class IdentityBrowserSession implements Session {

	private final Session delegate;
	private final Set<String> storedNames;
	private final Set<String> changes = new HashSet<>();
	private boolean fresh;
	private StoredState committedState;

	IdentityBrowserSession(Session delegate, boolean fresh) {
		this.delegate = delegate;
		this.fresh = fresh;
		this.storedNames = new HashSet<>(delegate.getAttributeNames());
	}

	Session delegate() {
		return this.delegate;
	}

	Set<String> changedAttributes() {
		return this.fresh ? Set.copyOf(getAttributeNames()) : Set.copyOf(this.changes);
	}

	StoredState saved() {
		var attributes = new HashMap<String, byte[]>();
		for (String name : getAttributeNames()) {
			attributes.put(name, SerializationUtils.serialize(getAttribute(name)));
		}
		this.committedState = null;
		this.fresh = false;
		this.storedNames.clear();
		this.storedNames.addAll(getAttributeNames());
		this.changes.clear();
		return new StoredState(getId(), getCreationTime(), getLastAccessedTime(), getMaxInactiveInterval(), Map.copyOf(attributes));
	}

	void committed(StoredState state) { this.committedState = state; }

	/** Only the same successfully committed state may bypass a repeated repository save. */
	boolean isUnchangedSinceCommit() {
		var state = this.committedState;
		return state != null && state.id().equals(getId()) && state.createdAt().equals(getCreationTime())
				&& state.lastAccessedAt().equals(getLastAccessedTime()) && state.maxInactiveInterval().equals(getMaxInactiveInterval())
				&& state.attributes().keySet().equals(getAttributeNames())
				&& state.attributes().entrySet().stream().allMatch(entry ->
						Arrays.equals(entry.getValue(), SerializationUtils.serialize(getAttribute(entry.getKey()))));
	}

	record StoredState(String id, Instant createdAt, Instant lastAccessedAt, Duration maxInactiveInterval, Map<String, byte[]> attributes) { }

	@Override
	public String getId() { return this.delegate.getId(); }

	@Override
	public String changeSessionId() { return this.delegate.changeSessionId(); }

	@Override
	public <T> T getAttribute(String name) { return this.delegate.getAttribute(name); }

	@Override
	public Set<String> getAttributeNames() { return this.delegate.getAttributeNames(); }

	@Override
	public void setAttribute(String name, Object value) {
		this.delegate.setAttribute(name, value);
		if (value != null || this.storedNames.contains(name)) {
			this.changes.add(name);
		}
		else {
			// Adding then removing a previously absent attribute cancels the JDBC delta.
			this.changes.remove(name);
		}
	}

	@Override
	public void removeAttribute(String name) { setAttribute(name, null); }

	@Override
	public Instant getCreationTime() { return this.delegate.getCreationTime(); }

	@Override
	public void setLastAccessedTime(Instant time) { this.delegate.setLastAccessedTime(time); }

	@Override
	public Instant getLastAccessedTime() { return this.delegate.getLastAccessedTime(); }

	@Override
	public void setMaxInactiveInterval(Duration interval) { this.delegate.setMaxInactiveInterval(interval); }

	@Override
	public Duration getMaxInactiveInterval() { return this.delegate.getMaxInactiveInterval(); }

	@Override
	public boolean isExpired() { return this.delegate.isExpired(); }
}
