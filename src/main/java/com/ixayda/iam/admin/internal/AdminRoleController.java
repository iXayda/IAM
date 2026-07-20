package com.ixayda.iam.admin.internal;

import com.ixayda.iam.admin.AdminRoleOperations;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class AdminRoleController {

	private final AdminRoleOperations roles;

	AdminRoleController(AdminRoleOperations roles) {
		this.roles = roles;
	}

	@GetMapping(value = AdminWebSecurityConfiguration.ROLES_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
	ResponseEntity<AdminRoleCatalogResponse> roles() {
		AdminRoleCatalogResponse response = new AdminRoleCatalogResponse(this.roles.findRoles()
			.stream()
			.map(AdminRoleResponse::from)
			.toList());
		return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(response);
	}

}
