package com.ixayda.iam.admin;

public final class AdminRoleNotFoundException extends RuntimeException {

	private final AdminRoleCode roleCode;

	public AdminRoleNotFoundException(AdminRoleCode roleCode) {
		super("Admin role was not found");
		this.roleCode = roleCode;
	}

	public AdminRoleCode roleCode() {
		return this.roleCode;
	}

}
