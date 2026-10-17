package com.ixayda.iam.security;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.springframework.session.Session;

/** Tracks public Session mutations without inspecting the JDBC implementation's private delta. */
final class IdentityBrowserSession implements Session {

	private final Session delegate;
	private final Set<String> storedNames;
	private final Set<String> changes = new HashSet<>();
	private boolean fresh;

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

	void saved() {
		this.fresh = false;
		this.storedNames.clear();
		this.storedNames.addAll(getAttributeNames());
		this.changes.clear();
	}

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
