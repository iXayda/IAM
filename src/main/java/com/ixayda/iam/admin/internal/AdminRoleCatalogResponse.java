package com.ixayda.iam.admin.internal;

import java.util.List;
import java.util.Objects;

record AdminRoleCatalogResponse(List<AdminRoleResponse> roles) {

	AdminRoleCatalogResponse {
		Objects.requireNonNull(roles, "Admin roles must not be null");
		roles = List.copyOf(roles);
	}

}
