package com.ixayda.iam.admin;

public final class AdminRoleBindingConcurrentUpdateException extends RuntimeException {

	private final AdminRoleBindingId bindingId;

	private final long expectedVersion;

	public AdminRoleBindingConcurrentUpdateException(AdminRoleBindingId bindingId, long expectedVersion) {
		super("Admin role binding changed concurrently");
		this.bindingId = bindingId;
		this.expectedVersion = expectedVersion;
	}

	public AdminRoleBindingId bindingId() {
		return this.bindingId;
	}

	public long expectedVersion() {
		return this.expectedVersion;
	}

}
