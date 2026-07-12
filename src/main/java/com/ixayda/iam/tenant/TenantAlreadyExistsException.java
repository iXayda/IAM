package com.ixayda.iam.tenant;

import java.util.Objects;

public final class TenantAlreadyExistsException extends RuntimeException {

	private final String slug;

	public TenantAlreadyExistsException(String slug) {
		super("Tenant slug already exists: " + slug);
		this.slug = Objects.requireNonNull(slug, "Tenant slug must not be null");
	}

	public String slug() {
		return this.slug;
	}

}
