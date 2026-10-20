package com.ixayda.iam.dto;

import java.util.List;
import java.util.UUID;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientConfigurationRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "显示名，NFC，1 至 128 个 Unicode 码点") String displayName,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "所属资源的完整 UUID") UUID resourceId,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "1 至 10 个精确 HTTPS 回调，合计不超过 1000 个 ASCII 字符；不接受重复、片段、通配符、逗号或用户信息") List<String> redirectUris,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "openid、profile、offline_access 的受控子集，必须包含 openid，不能重复") List<String> scopes,
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "所属资源的允许角色 UUID，最多 100 个，不能重复；不授予 IAM 管理资格") List<UUID> allowedRoleIds) {

	public IdentityClientConfigurationRequest {
		redirectUris = List.copyOf(redirectUris);
		scopes = List.copyOf(scopes);
		allowedRoleIds = List.copyOf(allowedRoleIds);
	}

}
