package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceSecretResponse(IdentityResourceCredentialResponse credential,
		@Schema(description = "仅本次成功轮换交付的秘密；仅供该资源服务端在线校验，不是应用客户端秘密", pattern = "^[A-Za-z0-9_-]{43}$") String secret) {

	@Override
	public String toString() { return "IdentityResourceSecretResponse[REDACTED]"; }

}
