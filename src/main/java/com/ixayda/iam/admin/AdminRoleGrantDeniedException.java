package com.ixayda.iam.admin;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.UserId;

public final class AdminRoleGrantDeniedException extends RuntimeException {

	private final TenantId tenantId;

	private final UserId actorUserId;

	private final AdminRoleCode roleCode;

	public AdminRoleGrantDeniedException(TenantId tenantId, UserId actorUserId, AdminRoleCode roleCode) {
		super("Administrator is not allowed to manage the requested role");
		this.tenantId = tenantId;
		this.actorUserId = actorUserId;
		this.roleCode = roleCode;
	}

	public TenantId tenantId() {
		return this.tenantId;
	}

	public UserId actorUserId() {
		return this.actorUserId;
	}

	public AdminRoleCode roleCode() {
		return this.roleCode;
	}

}
