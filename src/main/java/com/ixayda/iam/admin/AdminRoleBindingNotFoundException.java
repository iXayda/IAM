package com.ixayda.iam.admin;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public final class AdminRoleBindingNotFoundException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId userId;

	private final AdminRoleCode roleCode;

	public AdminRoleBindingNotFoundException(TenantId tenantId, UserId userId, AdminRoleCode roleCode) {
		super("Admin role binding was not found");
		this.tenantId = tenantId;
		this.userId = userId;
		this.roleCode = roleCode;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId userId() {
		return this.userId;
	}

	public AdminRoleCode roleCode() {
		return this.roleCode;
	}

}
