package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityClientSecretResponse(IdentityClientResponse client,
		@Schema(description = "仅本次创建或轮换交付的秘密；保存于应用服务端秘密管理设施，不可再次查询", pattern = "^[A-Za-z0-9_-]{43}$") String secret) {

	@Override
	public String toString() { return "IdentityClientSecretResponse[REDACTED]"; }

}
